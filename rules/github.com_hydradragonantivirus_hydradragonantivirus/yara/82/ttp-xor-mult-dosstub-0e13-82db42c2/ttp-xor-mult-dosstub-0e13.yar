rule TTP_XOR_MULT_DOSStub_0e13 {
  strings:
    $key_0e13 = { 5a 7b [2] 2e 63 [2] 69 61 [2] 2e 70 [2] 60 7c [2] 6c 76 [2] 7b 7d [2] 60 33 [2] 5d }

  condition:
    any of them
}