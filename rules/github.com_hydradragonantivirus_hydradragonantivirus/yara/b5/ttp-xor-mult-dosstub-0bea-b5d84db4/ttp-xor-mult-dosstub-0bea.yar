rule TTP_XOR_MULT_DOSStub_0bea {
  strings:
    $key_0bea = { 5f 82 [2] 2b 9a [2] 6c 98 [2] 2b 89 [2] 65 85 [2] 69 8f [2] 7e 84 [2] 65 ca [2] 58 }

  condition:
    any of them
}