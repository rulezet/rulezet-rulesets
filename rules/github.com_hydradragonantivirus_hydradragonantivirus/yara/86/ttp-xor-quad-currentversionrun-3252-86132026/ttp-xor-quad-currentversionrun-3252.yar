rule TTP_XOR_QUAD_CurrentVersionRun_3252 {
  strings:
    $key_3252 = { 61 3d [2] 45 33 [2] 6e 1f [2] 40 3d [2] 54 26 [2] 5b 3c [2] 45 21 [2] 47 20 [2] 5c 26 [2] 40 21 [2] 5c 0e }

  condition:
    any of them
}