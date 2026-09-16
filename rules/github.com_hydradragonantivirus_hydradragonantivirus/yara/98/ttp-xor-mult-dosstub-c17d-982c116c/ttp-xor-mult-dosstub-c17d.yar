rule TTP_XOR_MULT_DOSStub_c17d {
  strings:
    $key_c17d = { 95 15 [2] e1 0d [2] a6 0f [2] e1 1e [2] af 12 [2] a3 18 [2] b4 13 [2] af 5d [2] 92 }

  condition:
    any of them
}