rule TTP_XOR_MULT_DOSStub_570d {
  strings:
    $key_570d = { 03 65 [2] 77 7d [2] 30 7f [2] 77 6e [2] 39 62 [2] 35 68 [2] 22 63 [2] 39 2d [2] 04 }

  condition:
    any of them
}