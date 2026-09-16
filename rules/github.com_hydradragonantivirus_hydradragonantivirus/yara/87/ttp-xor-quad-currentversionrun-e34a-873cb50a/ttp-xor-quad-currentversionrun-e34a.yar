rule TTP_XOR_QUAD_CurrentVersionRun_e34a {
  strings:
    $key_e34a = { b0 25 [2] 94 2b [2] bf 07 [2] 91 25 [2] 85 3e [2] 8a 24 [2] 94 39 [2] 96 38 [2] 8d 3e [2] 91 39 [2] 8d 16 }

  condition:
    any of them
}