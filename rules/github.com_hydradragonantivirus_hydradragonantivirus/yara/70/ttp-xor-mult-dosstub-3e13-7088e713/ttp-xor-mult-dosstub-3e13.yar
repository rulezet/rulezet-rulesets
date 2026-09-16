rule TTP_XOR_MULT_DOSStub_3e13 {
  strings:
    $key_3e13 = { 6a 7b [2] 1e 63 [2] 59 61 [2] 1e 70 [2] 50 7c [2] 5c 76 [2] 4b 7d [2] 50 33 [2] 6d }

  condition:
    any of them
}