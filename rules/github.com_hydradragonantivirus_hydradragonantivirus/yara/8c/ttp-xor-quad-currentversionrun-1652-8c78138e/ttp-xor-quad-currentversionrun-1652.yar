rule TTP_XOR_QUAD_CurrentVersionRun_1652 {
  strings:
    $key_1652 = { 45 3d [2] 61 33 [2] 4a 1f [2] 64 3d [2] 70 26 [2] 7f 3c [2] 61 21 [2] 63 20 [2] 78 26 [2] 64 21 [2] 78 0e }

  condition:
    any of them
}