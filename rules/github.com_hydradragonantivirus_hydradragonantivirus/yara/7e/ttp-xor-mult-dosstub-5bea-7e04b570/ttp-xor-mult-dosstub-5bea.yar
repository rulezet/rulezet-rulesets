rule TTP_XOR_MULT_DOSStub_5bea {
  strings:
    $key_5bea = { 0f 82 [2] 7b 9a [2] 3c 98 [2] 7b 89 [2] 35 85 [2] 39 8f [2] 2e 84 [2] 35 ca [2] 08 }

  condition:
    any of them
}