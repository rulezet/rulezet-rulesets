rule TTP_XOR_QUAD_CurrentVersionRun_4f1c {
  strings:
    $key_4f1c = { 1c 73 [2] 38 7d [2] 13 51 [2] 3d 73 [2] 29 68 [2] 26 72 [2] 38 6f [2] 3a 6e [2] 21 68 [2] 3d 6f [2] 21 40 }

  condition:
    any of them
}