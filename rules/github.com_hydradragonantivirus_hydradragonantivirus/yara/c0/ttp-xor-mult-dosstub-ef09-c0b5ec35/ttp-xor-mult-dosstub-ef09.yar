rule TTP_XOR_MULT_DOSStub_ef09 {
  strings:
    $key_ef09 = { bb 61 [2] cf 79 [2] 88 7b [2] cf 6a [2] 81 66 [2] 8d 6c [2] 9a 67 [2] 81 29 [2] bc }

  condition:
    any of them
}