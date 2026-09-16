rule TTP_XOR_MULT_DOSStub_1bea {
  strings:
    $key_1bea = { 4f 82 [2] 3b 9a [2] 7c 98 [2] 3b 89 [2] 75 85 [2] 79 8f [2] 6e 84 [2] 75 ca [2] 48 }

  condition:
    any of them
}