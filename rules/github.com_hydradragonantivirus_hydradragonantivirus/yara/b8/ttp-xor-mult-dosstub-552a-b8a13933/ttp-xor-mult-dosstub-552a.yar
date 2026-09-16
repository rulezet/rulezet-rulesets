rule TTP_XOR_MULT_DOSStub_552a {
  strings:
    $key_552a = { 01 42 [2] 75 5a [2] 32 58 [2] 75 49 [2] 3b 45 [2] 37 4f [2] 20 44 [2] 3b 0a [2] 06 }

  condition:
    any of them
}