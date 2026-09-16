rule TTP_XOR_QUAD_CurrentVersionRun_7c3d {
  strings:
    $key_7c3d = { 2f 52 [2] 0b 5c [2] 20 70 [2] 0e 52 [2] 1a 49 [2] 15 53 [2] 0b 4e [2] 09 4f [2] 12 49 [2] 0e 4e [2] 12 61 }

  condition:
    any of them
}