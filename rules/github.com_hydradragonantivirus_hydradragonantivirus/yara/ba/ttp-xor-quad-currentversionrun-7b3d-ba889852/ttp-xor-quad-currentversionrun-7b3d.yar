rule TTP_XOR_QUAD_CurrentVersionRun_7b3d {
  strings:
    $key_7b3d = { 28 52 [2] 0c 5c [2] 27 70 [2] 09 52 [2] 1d 49 [2] 12 53 [2] 0c 4e [2] 0e 4f [2] 15 49 [2] 09 4e [2] 15 61 }

  condition:
    any of them
}