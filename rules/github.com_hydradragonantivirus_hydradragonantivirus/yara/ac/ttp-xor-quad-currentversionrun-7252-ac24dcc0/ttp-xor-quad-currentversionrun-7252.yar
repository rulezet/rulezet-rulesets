rule TTP_XOR_QUAD_CurrentVersionRun_7252 {
  strings:
    $key_7252 = { 21 3d [2] 05 33 [2] 2e 1f [2] 00 3d [2] 14 26 [2] 1b 3c [2] 05 21 [2] 07 20 [2] 1c 26 [2] 00 21 [2] 1c 0e }

  condition:
    any of them
}