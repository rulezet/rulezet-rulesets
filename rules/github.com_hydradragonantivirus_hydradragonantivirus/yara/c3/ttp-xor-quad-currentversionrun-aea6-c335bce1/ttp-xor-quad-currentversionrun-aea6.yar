rule TTP_XOR_QUAD_CurrentVersionRun_aea6 {
  strings:
    $key_aea6 = { fd c9 [2] d9 c7 [2] f2 eb [2] dc c9 [2] c8 d2 [2] c7 c8 [2] d9 d5 [2] db d4 [2] c0 d2 [2] dc d5 [2] c0 fa }

  condition:
    any of them
}