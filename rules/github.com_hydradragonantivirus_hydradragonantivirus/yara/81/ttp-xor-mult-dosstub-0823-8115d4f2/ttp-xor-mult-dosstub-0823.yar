rule TTP_XOR_MULT_DOSStub_0823 {
  strings:
    $key_0823 = { 5c 4b [2] 28 53 [2] 6f 51 [2] 28 40 [2] 66 4c [2] 6a 46 [2] 7d 4d [2] 66 03 [2] 5b }

  condition:
    any of them
}