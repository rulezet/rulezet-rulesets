rule TTP_XOR_MULT_DOSStub_2b35 {
  strings:
    $key_2b35 = { 7f 5d [2] 0b 45 [2] 4c 47 [2] 0b 56 [2] 45 5a [2] 49 50 [2] 5e 5b [2] 45 15 [2] 78 }

  condition:
    any of them
}