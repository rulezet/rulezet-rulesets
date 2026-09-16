rule TTP_XOR_QUAD_CurrentVersionRun_8bc7 {
  strings:
    $key_8bc7 = { d8 a8 [2] fc a6 [2] d7 8a [2] f9 a8 [2] ed b3 [2] e2 a9 [2] fc b4 [2] fe b5 [2] e5 b3 [2] f9 b4 [2] e5 9b }

  condition:
    any of them
}