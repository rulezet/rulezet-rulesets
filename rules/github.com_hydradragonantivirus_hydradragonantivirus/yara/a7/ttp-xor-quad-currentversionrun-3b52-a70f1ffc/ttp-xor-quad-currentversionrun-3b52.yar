rule TTP_XOR_QUAD_CurrentVersionRun_3b52 {
  strings:
    $key_3b52 = { 68 3d [2] 4c 33 [2] 67 1f [2] 49 3d [2] 5d 26 [2] 52 3c [2] 4c 21 [2] 4e 20 [2] 55 26 [2] 49 21 [2] 55 0e }

  condition:
    any of them
}