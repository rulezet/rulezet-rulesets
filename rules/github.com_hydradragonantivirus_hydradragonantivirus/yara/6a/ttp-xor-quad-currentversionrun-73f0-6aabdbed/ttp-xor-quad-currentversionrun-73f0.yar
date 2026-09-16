rule TTP_XOR_QUAD_CurrentVersionRun_73f0 {
  strings:
    $key_73f0 = { 20 9f [2] 04 91 [2] 2f bd [2] 01 9f [2] 15 84 [2] 1a 9e [2] 04 83 [2] 06 82 [2] 1d 84 [2] 01 83 [2] 1d ac }

  condition:
    any of them
}