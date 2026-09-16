rule TTP_XOR_QUAD_CurrentVersionRun_4a26 {
  strings:
    $key_4a26 = { 19 49 [2] 3d 47 [2] 16 6b [2] 38 49 [2] 2c 52 [2] 23 48 [2] 3d 55 [2] 3f 54 [2] 24 52 [2] 38 55 [2] 24 7a }

  condition:
    any of them
}