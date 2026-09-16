rule TTP_XOR_MULT_DOSStub_6b0a {
  strings:
    $key_6b0a = { 3f 62 [2] 4b 7a [2] 0c 78 [2] 4b 69 [2] 05 65 [2] 09 6f [2] 1e 64 [2] 05 2a [2] 38 }

  condition:
    any of them
}