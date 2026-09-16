rule TTP_XOR_QUAD_CurrentVersionRun_6252 {
  strings:
    $key_6252 = { 31 3d [2] 15 33 [2] 3e 1f [2] 10 3d [2] 04 26 [2] 0b 3c [2] 15 21 [2] 17 20 [2] 0c 26 [2] 10 21 [2] 0c 0e }

  condition:
    any of them
}