rule TTP_XOR_MULT_DOSStub_613a {
  strings:
    $key_613a = { 35 52 [2] 41 4a [2] 06 48 [2] 41 59 [2] 0f 55 [2] 03 5f [2] 14 54 [2] 0f 1a [2] 32 }

  condition:
    any of them
}