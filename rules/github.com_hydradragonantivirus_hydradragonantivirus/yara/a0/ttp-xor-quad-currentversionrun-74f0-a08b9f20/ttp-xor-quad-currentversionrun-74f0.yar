rule TTP_XOR_QUAD_CurrentVersionRun_74f0 {
  strings:
    $key_74f0 = { 27 9f [2] 03 91 [2] 28 bd [2] 06 9f [2] 12 84 [2] 1d 9e [2] 03 83 [2] 01 82 [2] 1a 84 [2] 06 83 [2] 1a ac }

  condition:
    any of them
}