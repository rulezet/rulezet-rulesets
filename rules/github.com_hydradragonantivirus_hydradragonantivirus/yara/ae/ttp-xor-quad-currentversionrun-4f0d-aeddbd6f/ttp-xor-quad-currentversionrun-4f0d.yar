rule TTP_XOR_QUAD_CurrentVersionRun_4f0d {
  strings:
    $key_4f0d = { 1c 62 [2] 38 6c [2] 13 40 [2] 3d 62 [2] 29 79 [2] 26 63 [2] 38 7e [2] 3a 7f [2] 21 79 [2] 3d 7e [2] 21 51 }

  condition:
    any of them
}