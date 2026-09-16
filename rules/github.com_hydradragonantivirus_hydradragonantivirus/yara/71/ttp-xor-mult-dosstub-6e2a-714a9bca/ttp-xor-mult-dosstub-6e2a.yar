rule TTP_XOR_MULT_DOSStub_6e2a {
  strings:
    $key_6e2a = { 3a 42 [2] 4e 5a [2] 09 58 [2] 4e 49 [2] 00 45 [2] 0c 4f [2] 1b 44 [2] 00 0a [2] 3d }

  condition:
    any of them
}