rule TTP_XOR_QUAD_CurrentVersionRun_6752 {
  strings:
    $key_6752 = { 34 3d [2] 10 33 [2] 3b 1f [2] 15 3d [2] 01 26 [2] 0e 3c [2] 10 21 [2] 12 20 [2] 09 26 [2] 15 21 [2] 09 0e }

  condition:
    any of them
}