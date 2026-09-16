rule TTP_XOR_QUAD_CurrentVersionRun_6633 {
  strings:
    $key_6633 = { 35 5c [2] 11 52 [2] 3a 7e [2] 14 5c [2] 00 47 [2] 0f 5d [2] 11 40 [2] 13 41 [2] 08 47 [2] 14 40 [2] 08 6f }

  condition:
    any of them
}