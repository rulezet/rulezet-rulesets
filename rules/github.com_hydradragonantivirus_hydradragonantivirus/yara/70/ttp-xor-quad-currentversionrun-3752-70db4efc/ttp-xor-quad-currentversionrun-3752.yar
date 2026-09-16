rule TTP_XOR_QUAD_CurrentVersionRun_3752 {
  strings:
    $key_3752 = { 64 3d [2] 40 33 [2] 6b 1f [2] 45 3d [2] 51 26 [2] 5e 3c [2] 40 21 [2] 42 20 [2] 59 26 [2] 45 21 [2] 59 0e }

  condition:
    any of them
}