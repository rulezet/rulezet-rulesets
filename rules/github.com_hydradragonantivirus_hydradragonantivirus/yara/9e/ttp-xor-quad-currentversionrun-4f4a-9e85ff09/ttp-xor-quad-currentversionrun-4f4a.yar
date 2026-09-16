rule TTP_XOR_QUAD_CurrentVersionRun_4f4a {
  strings:
    $key_4f4a = { 1c 25 [2] 38 2b [2] 13 07 [2] 3d 25 [2] 29 3e [2] 26 24 [2] 38 39 [2] 3a 38 [2] 21 3e [2] 3d 39 [2] 21 16 }

  condition:
    any of them
}