rule TTP_XOR_MULT_DOSStub_efe3 {
  strings:
    $key_efe3 = { bb 8b [2] cf 93 [2] 88 91 [2] cf 80 [2] 81 8c [2] 8d 86 [2] 9a 8d [2] 81 c3 [2] bc }

  condition:
    any of them
}