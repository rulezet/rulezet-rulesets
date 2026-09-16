rule TTP_XOR_QUAD_CurrentVersionRun_13f0 {
  strings:
    $key_13f0 = { 40 9f [2] 64 91 [2] 4f bd [2] 61 9f [2] 75 84 [2] 7a 9e [2] 64 83 [2] 66 82 [2] 7d 84 [2] 61 83 [2] 7d ac }

  condition:
    any of them
}