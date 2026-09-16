rule TTP_XOR_MULT_DOSStub_2703 {
  strings:
    $key_2703 = { 73 6b [2] 07 73 [2] 40 71 [2] 07 60 [2] 49 6c [2] 45 66 [2] 52 6d [2] 49 23 [2] 74 }

  condition:
    any of them
}