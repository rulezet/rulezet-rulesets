rule TTP_XOR_QUAD_CurrentVersionRun_aea8 {
  strings:
    $key_aea8 = { fd c7 [2] d9 c9 [2] f2 e5 [2] dc c7 [2] c8 dc [2] c7 c6 [2] d9 db [2] db da [2] c0 dc [2] dc db [2] c0 f4 }

  condition:
    any of them
}