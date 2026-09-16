rule TTP_XOR_MULT_DOSStub_060d {
  strings:
    $key_060d = { 52 65 [2] 26 7d [2] 61 7f [2] 26 6e [2] 68 62 [2] 64 68 [2] 73 63 [2] 68 2d [2] 55 }

  condition:
    any of them
}