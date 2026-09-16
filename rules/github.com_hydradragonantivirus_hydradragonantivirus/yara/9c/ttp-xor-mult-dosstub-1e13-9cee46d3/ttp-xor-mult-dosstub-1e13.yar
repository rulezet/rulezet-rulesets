rule TTP_XOR_MULT_DOSStub_1e13 {
  strings:
    $key_1e13 = { 4a 7b [2] 3e 63 [2] 79 61 [2] 3e 70 [2] 70 7c [2] 7c 76 [2] 6b 7d [2] 70 33 [2] 4d }

  condition:
    any of them
}