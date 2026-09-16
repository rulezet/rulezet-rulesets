rule TTP_XOR_QUAD_CurrentVersionRun_e35b {
  strings:
    $key_e35b = { b0 34 [2] 94 3a [2] bf 16 [2] 91 34 [2] 85 2f [2] 8a 35 [2] 94 28 [2] 96 29 [2] 8d 2f [2] 91 28 [2] 8d 07 }

  condition:
    any of them
}