rule TTP_XOR_QUAD_CurrentVersionRun_aeab {
  strings:
    $key_aeab = { fd c4 [2] d9 ca [2] f2 e6 [2] dc c4 [2] c8 df [2] c7 c5 [2] d9 d8 [2] db d9 [2] c0 df [2] dc d8 [2] c0 f7 }

  condition:
    any of them
}