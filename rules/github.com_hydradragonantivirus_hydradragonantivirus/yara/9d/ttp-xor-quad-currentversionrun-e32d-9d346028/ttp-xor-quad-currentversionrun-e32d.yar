rule TTP_XOR_QUAD_CurrentVersionRun_e32d {
  strings:
    $key_e32d = { b0 42 [2] 94 4c [2] bf 60 [2] 91 42 [2] 85 59 [2] 8a 43 [2] 94 5e [2] 96 5f [2] 8d 59 [2] 91 5e [2] 8d 71 }

  condition:
    any of them
}