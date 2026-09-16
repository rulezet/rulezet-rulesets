rule TTP_XOR_MULT_DOSStub_062a {
  strings:
    $key_062a = { 52 42 [2] 26 5a [2] 61 58 [2] 26 49 [2] 68 45 [2] 64 4f [2] 73 44 [2] 68 0a [2] 55 }

  condition:
    any of them
}