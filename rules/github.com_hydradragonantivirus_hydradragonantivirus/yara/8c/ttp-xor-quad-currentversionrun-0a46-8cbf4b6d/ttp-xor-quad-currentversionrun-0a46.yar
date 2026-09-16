rule TTP_XOR_QUAD_CurrentVersionRun_0a46 {
  strings:
    $key_0a46 = { 59 29 [2] 7d 27 [2] 56 0b [2] 78 29 [2] 6c 32 [2] 63 28 [2] 7d 35 [2] 7f 34 [2] 64 32 [2] 78 35 [2] 64 1a }

  condition:
    any of them
}