rule TTP_XOR_MULT_DOSStub_330a {
  strings:
    $key_330a = { 67 62 [2] 13 7a [2] 54 78 [2] 13 69 [2] 5d 65 [2] 51 6f [2] 46 64 [2] 5d 2a [2] 60 }

  condition:
    any of them
}