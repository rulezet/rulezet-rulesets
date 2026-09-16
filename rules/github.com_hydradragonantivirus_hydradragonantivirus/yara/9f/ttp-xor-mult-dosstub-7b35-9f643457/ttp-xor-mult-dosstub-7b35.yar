rule TTP_XOR_MULT_DOSStub_7b35 {
  strings:
    $key_7b35 = { 2f 5d [2] 5b 45 [2] 1c 47 [2] 5b 56 [2] 15 5a [2] 19 50 [2] 0e 5b [2] 15 15 [2] 28 }

  condition:
    any of them
}