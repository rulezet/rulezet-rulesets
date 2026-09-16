rule TTP_XOR_QUAD_CurrentVersionRun_3b1d {
  strings:
    $key_3b1d = { 68 72 [2] 4c 7c [2] 67 50 [2] 49 72 [2] 5d 69 [2] 52 73 [2] 4c 6e [2] 4e 6f [2] 55 69 [2] 49 6e [2] 55 41 }

  condition:
    any of them
}