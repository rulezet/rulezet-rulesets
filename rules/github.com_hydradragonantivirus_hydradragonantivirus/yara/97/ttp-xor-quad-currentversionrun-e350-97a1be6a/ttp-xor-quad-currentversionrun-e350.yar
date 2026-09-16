rule TTP_XOR_QUAD_CurrentVersionRun_e350 {
  strings:
    $key_e350 = { b0 3f [2] 94 31 [2] bf 1d [2] 91 3f [2] 85 24 [2] 8a 3e [2] 94 23 [2] 96 22 [2] 8d 24 [2] 91 23 [2] 8d 0c }

  condition:
    any of them
}