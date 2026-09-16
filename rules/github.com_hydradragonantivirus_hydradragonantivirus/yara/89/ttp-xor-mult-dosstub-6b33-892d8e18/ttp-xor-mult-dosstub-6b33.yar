rule TTP_XOR_MULT_DOSStub_6b33 {
  strings:
    $key_6b33 = { 3f 5b [2] 4b 43 [2] 0c 41 [2] 4b 50 [2] 05 5c [2] 09 56 [2] 1e 5d [2] 05 13 [2] 38 }

  condition:
    any of them
}