rule TTP_XOR_QUAD_CurrentVersionRun_aed2 {
  strings:
    $key_aed2 = { fd bd [2] d9 b3 [2] f2 9f [2] dc bd [2] c8 a6 [2] c7 bc [2] d9 a1 [2] db a0 [2] c0 a6 [2] dc a1 [2] c0 8e }

  condition:
    any of them
}