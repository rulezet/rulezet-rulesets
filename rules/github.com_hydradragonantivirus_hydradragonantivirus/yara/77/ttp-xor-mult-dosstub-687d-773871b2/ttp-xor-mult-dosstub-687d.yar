rule TTP_XOR_MULT_DOSStub_687d {
  strings:
    $key_687d = { 3c 15 [2] 48 0d [2] 0f 0f [2] 48 1e [2] 06 12 [2] 0a 18 [2] 1d 13 [2] 06 5d [2] 3b }

  condition:
    any of them
}