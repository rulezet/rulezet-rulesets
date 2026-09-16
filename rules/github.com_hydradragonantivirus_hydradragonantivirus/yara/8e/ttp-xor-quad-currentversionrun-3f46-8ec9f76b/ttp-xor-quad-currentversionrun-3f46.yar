rule TTP_XOR_QUAD_CurrentVersionRun_3f46 {
  strings:
    $key_3f46 = { 6c 29 [2] 48 27 [2] 63 0b [2] 4d 29 [2] 59 32 [2] 56 28 [2] 48 35 [2] 4a 34 [2] 51 32 [2] 4d 35 [2] 51 1a }

  condition:
    any of them
}