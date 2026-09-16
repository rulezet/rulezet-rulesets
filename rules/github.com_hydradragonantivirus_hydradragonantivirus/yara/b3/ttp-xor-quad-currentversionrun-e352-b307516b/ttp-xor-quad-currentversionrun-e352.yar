rule TTP_XOR_QUAD_CurrentVersionRun_e352 {
  strings:
    $key_e352 = { b0 3d [2] 94 33 [2] bf 1f [2] 91 3d [2] 85 26 [2] 8a 3c [2] 94 21 [2] 96 20 [2] 8d 26 [2] 91 21 [2] 8d 0e }

  condition:
    any of them
}