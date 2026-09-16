rule TTP_XOR_MULT_DOSStub_2b2a {
  strings:
    $key_2b2a = { 7f 42 [2] 0b 5a [2] 4c 58 [2] 0b 49 [2] 45 45 [2] 49 4f [2] 5e 44 [2] 45 0a [2] 78 }

  condition:
    any of them
}