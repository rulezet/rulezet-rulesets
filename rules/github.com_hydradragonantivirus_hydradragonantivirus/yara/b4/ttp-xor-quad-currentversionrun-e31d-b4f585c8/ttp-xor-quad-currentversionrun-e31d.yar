rule TTP_XOR_QUAD_CurrentVersionRun_e31d {
  strings:
    $key_e31d = { b0 72 [2] 94 7c [2] bf 50 [2] 91 72 [2] 85 69 [2] 8a 73 [2] 94 6e [2] 96 6f [2] 8d 69 [2] 91 6e [2] 8d 41 }

  condition:
    any of them
}