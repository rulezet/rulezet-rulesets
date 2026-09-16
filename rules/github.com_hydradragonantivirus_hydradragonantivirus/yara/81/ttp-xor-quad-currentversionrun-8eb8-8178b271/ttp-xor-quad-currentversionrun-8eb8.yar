rule TTP_XOR_QUAD_CurrentVersionRun_8eb8 {
  strings:
    $key_8eb8 = { dd d7 [2] f9 d9 [2] d2 f5 [2] fc d7 [2] e8 cc [2] e7 d6 [2] f9 cb [2] fb ca [2] e0 cc [2] fc cb [2] e0 e4 }

  condition:
    any of them
}