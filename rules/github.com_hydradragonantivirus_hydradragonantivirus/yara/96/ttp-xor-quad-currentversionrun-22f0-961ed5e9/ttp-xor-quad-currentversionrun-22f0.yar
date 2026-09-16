rule TTP_XOR_QUAD_CurrentVersionRun_22f0 {
  strings:
    $key_22f0 = { 71 9f [2] 55 91 [2] 7e bd [2] 50 9f [2] 44 84 [2] 4b 9e [2] 55 83 [2] 57 82 [2] 4c 84 [2] 50 83 [2] 4c ac }

  condition:
    any of them
}