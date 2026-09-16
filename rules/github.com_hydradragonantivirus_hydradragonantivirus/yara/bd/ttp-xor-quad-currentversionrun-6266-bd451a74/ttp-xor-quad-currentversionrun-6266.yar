rule TTP_XOR_QUAD_CurrentVersionRun_6266 {
  strings:
    $key_6266 = { 31 09 [2] 15 07 [2] 3e 2b [2] 10 09 [2] 04 12 [2] 0b 08 [2] 15 15 [2] 17 14 [2] 0c 12 [2] 10 15 [2] 0c 3a }

  condition:
    any of them
}