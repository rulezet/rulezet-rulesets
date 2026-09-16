rule TTP_XOR_MULT_DOSStub_b17d {
  strings:
    $key_b17d = { e5 15 [2] 91 0d [2] d6 0f [2] 91 1e [2] df 12 [2] d3 18 [2] c4 13 [2] df 5d [2] e2 }

  condition:
    any of them
}