rule TTP_XOR_MULT_DOSStub_280d {
  strings:
    $key_280d = { 7c 65 [2] 08 7d [2] 4f 7f [2] 08 6e [2] 46 62 [2] 4a 68 [2] 5d 63 [2] 46 2d [2] 7b }

  condition:
    any of them
}