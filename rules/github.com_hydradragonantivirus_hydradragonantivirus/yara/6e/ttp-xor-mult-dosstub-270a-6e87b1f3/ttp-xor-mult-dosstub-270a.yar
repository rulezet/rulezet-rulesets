rule TTP_XOR_MULT_DOSStub_270a {
  strings:
    $key_270a = { 73 62 [2] 07 7a [2] 40 78 [2] 07 69 [2] 49 65 [2] 45 6f [2] 52 64 [2] 49 2a [2] 74 }

  condition:
    any of them
}