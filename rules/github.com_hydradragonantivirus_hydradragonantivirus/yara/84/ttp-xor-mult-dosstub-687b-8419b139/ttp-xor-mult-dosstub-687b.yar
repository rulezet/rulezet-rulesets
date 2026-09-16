rule TTP_XOR_MULT_DOSStub_687b {
  strings:
    $key_687b = { 3c 13 [2] 48 0b [2] 0f 09 [2] 48 18 [2] 06 14 [2] 0a 1e [2] 1d 15 [2] 06 5b [2] 3b }

  condition:
    any of them
}