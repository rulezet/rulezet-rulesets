rule TTP_XOR_QUAD_CurrentVersionRun_5826 {
  strings:
    $key_5826 = { 0b 49 [2] 2f 47 [2] 04 6b [2] 2a 49 [2] 3e 52 [2] 31 48 [2] 2f 55 [2] 2d 54 [2] 36 52 [2] 2a 55 [2] 36 7a }

  condition:
    any of them
}