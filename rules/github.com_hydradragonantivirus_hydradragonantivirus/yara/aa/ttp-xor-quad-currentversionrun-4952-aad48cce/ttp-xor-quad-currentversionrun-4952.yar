rule TTP_XOR_QUAD_CurrentVersionRun_4952 {
  strings:
    $key_4952 = { 1a 3d [2] 3e 33 [2] 15 1f [2] 3b 3d [2] 2f 26 [2] 20 3c [2] 3e 21 [2] 3c 20 [2] 27 26 [2] 3b 21 [2] 27 0e }

  condition:
    any of them
}