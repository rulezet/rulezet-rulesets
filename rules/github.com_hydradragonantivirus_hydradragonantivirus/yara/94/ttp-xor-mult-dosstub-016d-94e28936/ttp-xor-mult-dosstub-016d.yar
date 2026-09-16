rule TTP_XOR_MULT_DOSStub_016d {
  strings:
    $key_016d = { 55 05 [2] 21 1d [2] 66 1f [2] 21 0e [2] 6f 02 [2] 63 08 [2] 74 03 [2] 6f 4d [2] 52 }

  condition:
    any of them
}