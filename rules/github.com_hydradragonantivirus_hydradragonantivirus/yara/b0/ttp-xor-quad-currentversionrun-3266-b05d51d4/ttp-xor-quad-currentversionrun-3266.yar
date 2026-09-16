rule TTP_XOR_QUAD_CurrentVersionRun_3266 {
  strings:
    $key_3266 = { 61 09 [2] 45 07 [2] 6e 2b [2] 40 09 [2] 54 12 [2] 5b 08 [2] 45 15 [2] 47 14 [2] 5c 12 [2] 40 15 [2] 5c 3a }

  condition:
    any of them
}