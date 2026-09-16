rule TTP_XOR_QUAD_CurrentVersionRun_e466 {
  strings:
    $key_e466 = { b7 09 [2] 93 07 [2] b8 2b [2] 96 09 [2] 82 12 [2] 8d 08 [2] 93 15 [2] 91 14 [2] 8a 12 [2] 96 15 [2] 8a 3a }

  condition:
    any of them
}