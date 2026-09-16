rule TTP_XOR_QUAD_CurrentVersionRun_0752 {
  strings:
    $key_0752 = { 54 3d [2] 70 33 [2] 5b 1f [2] 75 3d [2] 61 26 [2] 6e 3c [2] 70 21 [2] 72 20 [2] 69 26 [2] 75 21 [2] 69 0e }

  condition:
    any of them
}