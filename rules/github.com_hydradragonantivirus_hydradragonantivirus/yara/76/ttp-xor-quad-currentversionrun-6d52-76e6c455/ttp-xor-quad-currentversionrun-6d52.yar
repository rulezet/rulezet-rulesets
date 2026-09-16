rule TTP_XOR_QUAD_CurrentVersionRun_6d52 {
  strings:
    $key_6d52 = { 3e 3d [2] 1a 33 [2] 31 1f [2] 1f 3d [2] 0b 26 [2] 04 3c [2] 1a 21 [2] 18 20 [2] 03 26 [2] 1f 21 [2] 03 0e }

  condition:
    any of them
}