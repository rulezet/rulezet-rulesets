rule TTP_XOR_QUAD_CurrentVersionRun_e37f {
  strings:
    $key_e37f = { b0 10 [2] 94 1e [2] bf 32 [2] 91 10 [2] 85 0b [2] 8a 11 [2] 94 0c [2] 96 0d [2] 8d 0b [2] 91 0c [2] 8d 23 }

  condition:
    any of them
}