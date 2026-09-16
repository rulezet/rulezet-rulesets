rule TTP_XOR_QUAD_CurrentVersionRun_4f12 {
  strings:
    $key_4f12 = { 1c 7d [2] 38 73 [2] 13 5f [2] 3d 7d [2] 29 66 [2] 26 7c [2] 38 61 [2] 3a 60 [2] 21 66 [2] 3d 61 [2] 21 4e }

  condition:
    any of them
}