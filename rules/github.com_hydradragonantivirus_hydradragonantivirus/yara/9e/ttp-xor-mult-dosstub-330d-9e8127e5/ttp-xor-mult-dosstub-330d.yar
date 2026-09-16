rule TTP_XOR_MULT_DOSStub_330d {
  strings:
    $key_330d = { 67 65 [2] 13 7d [2] 54 7f [2] 13 6e [2] 5d 62 [2] 51 68 [2] 46 63 [2] 5d 2d [2] 60 }

  condition:
    any of them
}