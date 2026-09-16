rule TTP_XOR_QUAD_CurrentVersionRun_63f0 {
  strings:
    $key_63f0 = { 30 9f [2] 14 91 [2] 3f bd [2] 11 9f [2] 05 84 [2] 0a 9e [2] 14 83 [2] 16 82 [2] 0d 84 [2] 11 83 [2] 0d ac }

  condition:
    any of them
}