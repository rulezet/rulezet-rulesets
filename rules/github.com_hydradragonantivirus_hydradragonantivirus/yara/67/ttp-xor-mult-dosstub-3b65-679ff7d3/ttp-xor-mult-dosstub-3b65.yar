rule TTP_XOR_MULT_DOSStub_3b65 {
  strings:
    $key_3b65 = { 6f 0d [2] 1b 15 [2] 5c 17 [2] 1b 06 [2] 55 0a [2] 59 00 [2] 4e 0b [2] 55 45 [2] 68 }

  condition:
    any of them
}