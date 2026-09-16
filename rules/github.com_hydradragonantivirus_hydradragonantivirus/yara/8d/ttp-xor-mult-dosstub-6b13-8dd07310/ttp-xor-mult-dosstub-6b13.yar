rule TTP_XOR_MULT_DOSStub_6b13 {
  strings:
    $key_6b13 = { 3f 7b [2] 4b 63 [2] 0c 61 [2] 4b 70 [2] 05 7c [2] 09 76 [2] 1e 7d [2] 05 33 [2] 38 }

  condition:
    any of them
}