rule TTP_XOR_QUAD_CurrentVersionRun_6603 {
  strings:
    $key_6603 = { 35 6c [2] 11 62 [2] 3a 4e [2] 14 6c [2] 00 77 [2] 0f 6d [2] 11 70 [2] 13 71 [2] 08 77 [2] 14 70 [2] 08 5f }

  condition:
    any of them
}