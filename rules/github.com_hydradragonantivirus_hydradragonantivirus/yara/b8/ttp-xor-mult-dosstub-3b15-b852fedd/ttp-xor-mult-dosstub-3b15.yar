rule TTP_XOR_MULT_DOSStub_3b15 {
  strings:
    $key_3b15 = { 6f 7d [2] 1b 65 [2] 5c 67 [2] 1b 76 [2] 55 7a [2] 59 70 [2] 4e 7b [2] 55 35 [2] 68 }

  condition:
    any of them
}