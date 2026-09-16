rule TTP_XOR_MULT_DOSStub_0b35 {
  strings:
    $key_0b35 = { 5f 5d [2] 2b 45 [2] 6c 47 [2] 2b 56 [2] 65 5a [2] 69 50 [2] 7e 5b [2] 65 15 [2] 58 }

  condition:
    any of them
}