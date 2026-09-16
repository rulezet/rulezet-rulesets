rule TTP_XOR_MULT_DOSStub_e30d {
  strings:
    $key_e30d = { b7 65 [2] c3 7d [2] 84 7f [2] c3 6e [2] 8d 62 [2] 81 68 [2] 96 63 [2] 8d 2d [2] b0 }

  condition:
    any of them
}