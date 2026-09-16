rule TTP_XOR_QUAD_CurrentVersionRun_e31f {
  strings:
    $key_e31f = { b0 70 [2] 94 7e [2] bf 52 [2] 91 70 [2] 85 6b [2] 8a 71 [2] 94 6c [2] 96 6d [2] 8d 6b [2] 91 6c [2] 8d 43 }

  condition:
    any of them
}