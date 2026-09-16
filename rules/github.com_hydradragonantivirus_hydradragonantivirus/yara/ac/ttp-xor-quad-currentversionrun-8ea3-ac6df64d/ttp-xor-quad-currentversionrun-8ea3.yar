rule TTP_XOR_QUAD_CurrentVersionRun_8ea3 {
  strings:
    $key_8ea3 = { dd cc [2] f9 c2 [2] d2 ee [2] fc cc [2] e8 d7 [2] e7 cd [2] f9 d0 [2] fb d1 [2] e0 d7 [2] fc d0 [2] e0 ff }

  condition:
    any of them
}