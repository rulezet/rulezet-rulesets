rule TTP_XOR_QUAD_CurrentVersionRun_3452 {
  strings:
    $key_3452 = { 67 3d [2] 43 33 [2] 68 1f [2] 46 3d [2] 52 26 [2] 5d 3c [2] 43 21 [2] 41 20 [2] 5a 26 [2] 46 21 [2] 5a 0e }

  condition:
    any of them
}