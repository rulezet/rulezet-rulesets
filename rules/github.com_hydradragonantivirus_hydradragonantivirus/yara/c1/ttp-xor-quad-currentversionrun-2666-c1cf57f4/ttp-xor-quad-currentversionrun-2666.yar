rule TTP_XOR_QUAD_CurrentVersionRun_2666 {
  strings:
    $key_2666 = { 75 09 [2] 51 07 [2] 7a 2b [2] 54 09 [2] 40 12 [2] 4f 08 [2] 51 15 [2] 53 14 [2] 48 12 [2] 54 15 [2] 48 3a }

  condition:
    any of them
}