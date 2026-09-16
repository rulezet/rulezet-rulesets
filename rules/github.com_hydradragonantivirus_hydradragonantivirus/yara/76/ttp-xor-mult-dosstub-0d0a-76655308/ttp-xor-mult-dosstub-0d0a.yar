rule TTP_XOR_MULT_DOSStub_0d0a {
  strings:
    $key_0d0a = { 59 62 [2] 2d 7a [2] 6a 78 [2] 2d 69 [2] 63 65 [2] 6f 6f [2] 78 64 [2] 63 2a [2] 5e }

  condition:
    any of them
}