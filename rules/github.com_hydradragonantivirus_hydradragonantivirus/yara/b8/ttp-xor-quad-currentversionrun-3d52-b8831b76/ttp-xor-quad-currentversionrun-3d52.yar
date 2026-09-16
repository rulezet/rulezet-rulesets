rule TTP_XOR_QUAD_CurrentVersionRun_3d52 {
  strings:
    $key_3d52 = { 6e 3d [2] 4a 33 [2] 61 1f [2] 4f 3d [2] 5b 26 [2] 54 3c [2] 4a 21 [2] 48 20 [2] 53 26 [2] 4f 21 [2] 53 0e }

  condition:
    any of them
}