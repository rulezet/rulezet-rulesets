rule TTP_XOR_QUAD_CurrentVersionRun_91f0 {
  strings:
    $key_91f0 = { c2 9f [2] e6 91 [2] cd bd [2] e3 9f [2] f7 84 [2] f8 9e [2] e6 83 [2] e4 82 [2] ff 84 [2] e3 83 [2] ff ac }

  condition:
    any of them
}