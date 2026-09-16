rule TTP_XOR_QUAD_CurrentVersionRun_e661 {
  strings:
    $key_e661 = { b5 0e [2] 91 00 [2] ba 2c [2] 94 0e [2] 80 15 [2] 8f 0f [2] 91 12 [2] 93 13 [2] 88 15 [2] 94 12 [2] 88 3d }

  condition:
    any of them
}