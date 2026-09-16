rule TTP_XOR_MULT_DOSStub_2713 {
  strings:
    $key_2713 = { 73 7b [2] 07 63 [2] 40 61 [2] 07 70 [2] 49 7c [2] 45 76 [2] 52 7d [2] 49 33 [2] 74 }

  condition:
    any of them
}