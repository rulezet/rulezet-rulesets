rule TTP_XOR_QUAD_CurrentVersionRun_4a76 {
  strings:
    $key_4a76 = { 19 19 [2] 3d 17 [2] 16 3b [2] 38 19 [2] 2c 02 [2] 23 18 [2] 3d 05 [2] 3f 04 [2] 24 02 [2] 38 05 [2] 24 2a }

  condition:
    any of them
}