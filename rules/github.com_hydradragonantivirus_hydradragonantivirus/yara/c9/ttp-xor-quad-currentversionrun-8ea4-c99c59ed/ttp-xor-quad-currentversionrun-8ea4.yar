rule TTP_XOR_QUAD_CurrentVersionRun_8ea4 {
  strings:
    $key_8ea4 = { dd cb [2] f9 c5 [2] d2 e9 [2] fc cb [2] e8 d0 [2] e7 ca [2] f9 d7 [2] fb d6 [2] e0 d0 [2] fc d7 [2] e0 f8 }

  condition:
    any of them
}