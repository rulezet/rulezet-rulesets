rule TTP_XOR_QUAD_CurrentVersionRun_6620 {
  strings:
    $key_6620 = { 35 4f [2] 11 41 [2] 3a 6d [2] 14 4f [2] 00 54 [2] 0f 4e [2] 11 53 [2] 13 52 [2] 08 54 [2] 14 53 [2] 08 7c }

  condition:
    any of them
}