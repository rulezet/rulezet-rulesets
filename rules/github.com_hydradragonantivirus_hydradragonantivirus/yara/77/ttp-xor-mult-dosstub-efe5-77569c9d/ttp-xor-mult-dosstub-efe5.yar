rule TTP_XOR_MULT_DOSStub_efe5 {
  strings:
    $key_efe5 = { bb 8d [2] cf 95 [2] 88 97 [2] cf 86 [2] 81 8a [2] 8d 80 [2] 9a 8b [2] 81 c5 [2] bc }

  condition:
    any of them
}