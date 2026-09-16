rule TTP_XOR_QUAD_CurrentVersionRun_3952 {
  strings:
    $key_3952 = { 6a 3d [2] 4e 33 [2] 65 1f [2] 4b 3d [2] 5f 26 [2] 50 3c [2] 4e 21 [2] 4c 20 [2] 57 26 [2] 4b 21 [2] 57 0e }

  condition:
    any of them
}