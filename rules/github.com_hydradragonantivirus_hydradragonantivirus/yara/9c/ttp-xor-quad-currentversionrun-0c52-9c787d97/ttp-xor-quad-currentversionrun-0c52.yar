rule TTP_XOR_QUAD_CurrentVersionRun_0c52 {
  strings:
    $key_0c52 = { 5f 3d [2] 7b 33 [2] 50 1f [2] 7e 3d [2] 6a 26 [2] 65 3c [2] 7b 21 [2] 79 20 [2] 62 26 [2] 7e 21 [2] 62 0e }

  condition:
    any of them
}