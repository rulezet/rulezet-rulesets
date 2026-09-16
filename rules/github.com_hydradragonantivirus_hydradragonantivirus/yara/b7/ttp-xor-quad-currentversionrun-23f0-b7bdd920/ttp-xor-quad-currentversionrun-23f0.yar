rule TTP_XOR_QUAD_CurrentVersionRun_23f0 {
  strings:
    $key_23f0 = { 70 9f [2] 54 91 [2] 7f bd [2] 51 9f [2] 45 84 [2] 4a 9e [2] 54 83 [2] 56 82 [2] 4d 84 [2] 51 83 [2] 4d ac }

  condition:
    any of them
}