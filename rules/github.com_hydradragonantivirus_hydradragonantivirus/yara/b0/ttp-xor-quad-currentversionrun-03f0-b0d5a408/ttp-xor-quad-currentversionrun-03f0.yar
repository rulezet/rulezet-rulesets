rule TTP_XOR_QUAD_CurrentVersionRun_03f0 {
  strings:
    $key_03f0 = { 50 9f [2] 74 91 [2] 5f bd [2] 71 9f [2] 65 84 [2] 6a 9e [2] 74 83 [2] 76 82 [2] 6d 84 [2] 71 83 [2] 6d ac }

  condition:
    any of them
}