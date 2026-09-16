rule TTP_XOR_MULT_DOSStub_1f0a {
  strings:
    $key_1f0a = { 4b 62 [2] 3f 7a [2] 78 78 [2] 3f 69 [2] 71 65 [2] 7d 6f [2] 6a 64 [2] 71 2a [2] 4c }

  condition:
    any of them
}