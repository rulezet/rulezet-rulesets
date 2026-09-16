rule TTP_XOR_QUAD_CurrentVersionRun_c51a {
  strings:
    $key_c51a = { 96 75 [2] b2 7b [2] 99 57 [2] b7 75 [2] a3 6e [2] ac 74 [2] b2 69 [2] b0 68 [2] ab 6e [2] b7 69 [2] ab 46 }

  condition:
    any of them
}