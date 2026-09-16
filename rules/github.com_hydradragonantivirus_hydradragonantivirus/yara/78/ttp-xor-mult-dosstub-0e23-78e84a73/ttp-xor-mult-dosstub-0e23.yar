rule TTP_XOR_MULT_DOSStub_0e23 {
  strings:
    $key_0e23 = { 5a 4b [2] 2e 53 [2] 69 51 [2] 2e 40 [2] 60 4c [2] 6c 46 [2] 7b 4d [2] 60 03 [2] 5d }

  condition:
    any of them
}