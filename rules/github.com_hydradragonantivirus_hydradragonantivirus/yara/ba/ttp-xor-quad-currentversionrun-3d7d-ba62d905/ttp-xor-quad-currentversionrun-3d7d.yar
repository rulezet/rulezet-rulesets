rule TTP_XOR_QUAD_CurrentVersionRun_3d7d {
  strings:
    $key_3d7d = { 6e 12 [2] 4a 1c [2] 61 30 [2] 4f 12 [2] 5b 09 [2] 54 13 [2] 4a 0e [2] 48 0f [2] 53 09 [2] 4f 0e [2] 53 21 }

  condition:
    any of them
}