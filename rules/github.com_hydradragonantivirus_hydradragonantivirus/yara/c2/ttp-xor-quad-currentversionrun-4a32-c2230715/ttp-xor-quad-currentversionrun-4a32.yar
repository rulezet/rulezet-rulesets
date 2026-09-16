rule TTP_XOR_QUAD_CurrentVersionRun_4a32 {
  strings:
    $key_4a32 = { 19 5d [2] 3d 53 [2] 16 7f [2] 38 5d [2] 2c 46 [2] 23 5c [2] 3d 41 [2] 3f 40 [2] 24 46 [2] 38 41 [2] 24 6e }

  condition:
    any of them
}