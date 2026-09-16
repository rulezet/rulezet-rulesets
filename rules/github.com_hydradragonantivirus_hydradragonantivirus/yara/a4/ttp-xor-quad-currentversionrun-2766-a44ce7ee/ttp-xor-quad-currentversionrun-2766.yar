rule TTP_XOR_QUAD_CurrentVersionRun_2766 {
  strings:
    $key_2766 = { 74 09 [2] 50 07 [2] 7b 2b [2] 55 09 [2] 41 12 [2] 4e 08 [2] 50 15 [2] 52 14 [2] 49 12 [2] 55 15 [2] 49 3a }

  condition:
    any of them
}