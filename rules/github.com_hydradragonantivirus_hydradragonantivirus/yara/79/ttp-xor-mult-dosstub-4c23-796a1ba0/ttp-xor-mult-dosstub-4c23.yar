rule TTP_XOR_MULT_DOSStub_4c23 {
  strings:
    $key_4c23 = { 18 4b [2] 6c 53 [2] 2b 51 [2] 6c 40 [2] 22 4c [2] 2e 46 [2] 39 4d [2] 22 03 [2] 1f }

  condition:
    any of them
}