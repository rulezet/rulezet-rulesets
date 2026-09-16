rule TTP_XOR_QUAD_CurrentVersionRun_601d {
  strings:
    $key_601d = { 33 72 [2] 17 7c [2] 3c 50 [2] 12 72 [2] 06 69 [2] 09 73 [2] 17 6e [2] 15 6f [2] 0e 69 [2] 12 6e [2] 0e 41 }

  condition:
    any of them
}