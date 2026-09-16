rule TTP_XOR_MULT_DOSStub_482a {
  strings:
    $key_482a = { 1c 42 [2] 68 5a [2] 2f 58 [2] 68 49 [2] 26 45 [2] 2a 4f [2] 3d 44 [2] 26 0a [2] 1b }

  condition:
    any of them
}