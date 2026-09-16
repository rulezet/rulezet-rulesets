rule TTP_XOR_QUAD_CurrentVersionRun_4fec {
  strings:
    $key_4fec = { 1c 83 [2] 38 8d [2] 13 a1 [2] 3d 83 [2] 29 98 [2] 26 82 [2] 38 9f [2] 3a 9e [2] 21 98 [2] 3d 9f [2] 21 b0 }

  condition:
    any of them
}