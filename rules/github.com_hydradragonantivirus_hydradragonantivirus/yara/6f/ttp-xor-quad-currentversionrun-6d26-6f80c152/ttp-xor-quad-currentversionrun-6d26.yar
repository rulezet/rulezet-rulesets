rule TTP_XOR_QUAD_CurrentVersionRun_6d26 {
  strings:
    $key_6d26 = { 3e 49 [2] 1a 47 [2] 31 6b [2] 1f 49 [2] 0b 52 [2] 04 48 [2] 1a 55 [2] 18 54 [2] 03 52 [2] 1f 55 [2] 03 7a }

  condition:
    any of them
}