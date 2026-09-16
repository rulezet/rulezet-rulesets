rule TTP_XOR_MULT_DOSStub_687f {
  strings:
    $key_687f = { 3c 17 [2] 48 0f [2] 0f 0d [2] 48 1c [2] 06 10 [2] 0a 1a [2] 1d 11 [2] 06 5f [2] 3b }

  condition:
    any of them
}