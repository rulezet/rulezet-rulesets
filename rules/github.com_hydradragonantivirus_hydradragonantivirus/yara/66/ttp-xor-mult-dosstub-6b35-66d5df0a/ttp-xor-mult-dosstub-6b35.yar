rule TTP_XOR_MULT_DOSStub_6b35 {
  strings:
    $key_6b35 = { 3f 5d [2] 4b 45 [2] 0c 47 [2] 4b 56 [2] 05 5a [2] 09 50 [2] 1e 5b [2] 05 15 [2] 38 }

  condition:
    any of them
}