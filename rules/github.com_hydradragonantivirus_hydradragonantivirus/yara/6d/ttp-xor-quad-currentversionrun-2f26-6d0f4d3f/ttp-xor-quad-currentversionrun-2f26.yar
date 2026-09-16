rule TTP_XOR_QUAD_CurrentVersionRun_2f26 {
  strings:
    $key_2f26 = { 7c 49 [2] 58 47 [2] 73 6b [2] 5d 49 [2] 49 52 [2] 46 48 [2] 58 55 [2] 5a 54 [2] 41 52 [2] 5d 55 [2] 41 7a }

  condition:
    any of them
}