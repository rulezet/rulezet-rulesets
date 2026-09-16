rule TTP_XOR_QUAD_CurrentVersionRun_491d {
  strings:
    $key_491d = { 1a 72 [2] 3e 7c [2] 15 50 [2] 3b 72 [2] 2f 69 [2] 20 73 [2] 3e 6e [2] 3c 6f [2] 27 69 [2] 3b 6e [2] 27 41 }

  condition:
    any of them
}