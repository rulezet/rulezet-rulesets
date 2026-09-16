rule TTP_XOR_MULT_DOSStub_4bea {
  strings:
    $key_4bea = { 1f 82 [2] 6b 9a [2] 2c 98 [2] 6b 89 [2] 25 85 [2] 29 8f [2] 3e 84 [2] 25 ca [2] 18 }

  condition:
    any of them
}