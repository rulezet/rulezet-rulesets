rule TTP_XOR_QUAD_CurrentVersionRun_d752 {
  strings:
    $key_d752 = { 84 3d [2] a0 33 [2] 8b 1f [2] a5 3d [2] b1 26 [2] be 3c [2] a0 21 [2] a2 20 [2] b9 26 [2] a5 21 [2] b9 0e }

  condition:
    any of them
}