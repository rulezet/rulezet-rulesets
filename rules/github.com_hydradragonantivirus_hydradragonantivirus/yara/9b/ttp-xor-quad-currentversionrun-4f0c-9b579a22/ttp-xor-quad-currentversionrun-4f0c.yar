rule TTP_XOR_QUAD_CurrentVersionRun_4f0c {
  strings:
    $key_4f0c = { 1c 63 [2] 38 6d [2] 13 41 [2] 3d 63 [2] 29 78 [2] 26 62 [2] 38 7f [2] 3a 7e [2] 21 78 [2] 3d 7f [2] 21 50 }

  condition:
    any of them
}