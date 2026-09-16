rule TTP_XOR_MULT_DOSStub_280a {
  strings:
    $key_280a = { 7c 62 [2] 08 7a [2] 4f 78 [2] 08 69 [2] 46 65 [2] 4a 6f [2] 5d 64 [2] 46 2a [2] 7b }

  condition:
    any of them
}