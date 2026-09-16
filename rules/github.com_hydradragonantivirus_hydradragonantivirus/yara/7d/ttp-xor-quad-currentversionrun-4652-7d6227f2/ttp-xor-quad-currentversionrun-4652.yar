rule TTP_XOR_QUAD_CurrentVersionRun_4652 {
  strings:
    $key_4652 = { 15 3d [2] 31 33 [2] 1a 1f [2] 34 3d [2] 20 26 [2] 2f 3c [2] 31 21 [2] 33 20 [2] 28 26 [2] 34 21 [2] 28 0e }

  condition:
    any of them
}