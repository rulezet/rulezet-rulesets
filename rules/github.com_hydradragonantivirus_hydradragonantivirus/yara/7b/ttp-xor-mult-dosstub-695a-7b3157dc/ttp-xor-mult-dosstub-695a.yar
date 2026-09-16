rule TTP_XOR_MULT_DOSStub_695a {
  strings:
    $key_695a = { 3d 32 [2] 49 2a [2] 0e 28 [2] 49 39 [2] 07 35 [2] 0b 3f [2] 1c 34 [2] 07 7a [2] 3a }

  condition:
    any of them
}