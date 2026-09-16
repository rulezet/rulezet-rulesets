rule TTP_XOR_MULT_DOSStub_2b65 {
  strings:
    $key_2b65 = { 7f 0d [2] 0b 15 [2] 4c 17 [2] 0b 06 [2] 45 0a [2] 49 00 [2] 5e 0b [2] 45 45 [2] 78 }

  condition:
    any of them
}