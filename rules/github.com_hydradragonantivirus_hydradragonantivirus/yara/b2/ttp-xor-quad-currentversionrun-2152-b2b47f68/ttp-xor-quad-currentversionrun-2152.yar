rule TTP_XOR_QUAD_CurrentVersionRun_2152 {
  strings:
    $key_2152 = { 72 3d [2] 56 33 [2] 7d 1f [2] 53 3d [2] 47 26 [2] 48 3c [2] 56 21 [2] 54 20 [2] 4f 26 [2] 53 21 [2] 4f 0e }

  condition:
    any of them
}