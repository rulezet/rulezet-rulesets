rule TTP_XOR_QUAD_CurrentVersionRun_e320 {
  strings:
    $key_e320 = { b0 4f [2] 94 41 [2] bf 6d [2] 91 4f [2] 85 54 [2] 8a 4e [2] 94 53 [2] 96 52 [2] 8d 54 [2] 91 53 [2] 8d 7c }

  condition:
    any of them
}