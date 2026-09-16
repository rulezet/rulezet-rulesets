rule TTP_XOR_QUAD_CurrentVersionRun_5552 {
  strings:
    $key_5552 = { 06 3d [2] 22 33 [2] 09 1f [2] 27 3d [2] 33 26 [2] 3c 3c [2] 22 21 [2] 20 20 [2] 3b 26 [2] 27 21 [2] 3b 0e }

  condition:
    any of them
}