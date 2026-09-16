rule TTP_XOR_QUAD_CurrentVersionRun_e351 {
  strings:
    $key_e351 = { b0 3e [2] 94 30 [2] bf 1c [2] 91 3e [2] 85 25 [2] 8a 3f [2] 94 22 [2] 96 23 [2] 8d 25 [2] 91 22 [2] 8d 0d }

  condition:
    any of them
}