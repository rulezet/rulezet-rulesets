rule TTP_XOR_QUAD_CurrentVersionRun_0e52 {
  strings:
    $key_0e52 = { 5d 3d [2] 79 33 [2] 52 1f [2] 7c 3d [2] 68 26 [2] 67 3c [2] 79 21 [2] 7b 20 [2] 60 26 [2] 7c 21 [2] 60 0e }

  condition:
    any of them
}