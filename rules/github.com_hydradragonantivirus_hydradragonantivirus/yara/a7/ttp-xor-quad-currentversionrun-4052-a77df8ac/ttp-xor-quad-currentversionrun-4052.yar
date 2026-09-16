rule TTP_XOR_QUAD_CurrentVersionRun_4052 {
  strings:
    $key_4052 = { 13 3d [2] 37 33 [2] 1c 1f [2] 32 3d [2] 26 26 [2] 29 3c [2] 37 21 [2] 35 20 [2] 2e 26 [2] 32 21 [2] 2e 0e }

  condition:
    any of them
}