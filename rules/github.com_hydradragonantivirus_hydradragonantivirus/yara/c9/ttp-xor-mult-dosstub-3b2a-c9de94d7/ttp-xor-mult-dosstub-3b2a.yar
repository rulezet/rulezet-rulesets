rule TTP_XOR_MULT_DOSStub_3b2a {
  strings:
    $key_3b2a = { 6f 42 [2] 1b 5a [2] 5c 58 [2] 1b 49 [2] 55 45 [2] 59 4f [2] 4e 44 [2] 55 0a [2] 68 }

  condition:
    any of them
}