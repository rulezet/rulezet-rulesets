rule TTP_XOR_MULT_DOSStub_2702 {
  strings:
    $key_2702 = { 73 6a [2] 07 72 [2] 40 70 [2] 07 61 [2] 49 6d [2] 45 67 [2] 52 6c [2] 49 22 [2] 74 }

  condition:
    any of them
}