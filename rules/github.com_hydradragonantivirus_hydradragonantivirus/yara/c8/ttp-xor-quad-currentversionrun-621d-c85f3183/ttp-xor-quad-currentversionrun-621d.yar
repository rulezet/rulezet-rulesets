rule TTP_XOR_QUAD_CurrentVersionRun_621d {
  strings:
    $key_621d = { 31 72 [2] 15 7c [2] 3e 50 [2] 10 72 [2] 04 69 [2] 0b 73 [2] 15 6e [2] 17 6f [2] 0c 69 [2] 10 6e [2] 0c 41 }

  condition:
    any of them
}