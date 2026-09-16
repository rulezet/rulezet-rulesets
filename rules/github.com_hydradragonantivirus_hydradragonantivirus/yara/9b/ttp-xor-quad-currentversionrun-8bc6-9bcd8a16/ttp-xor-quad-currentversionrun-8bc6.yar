rule TTP_XOR_QUAD_CurrentVersionRun_8bc6 {
  strings:
    $key_8bc6 = { d8 a9 [2] fc a7 [2] d7 8b [2] f9 a9 [2] ed b2 [2] e2 a8 [2] fc b5 [2] fe b4 [2] e5 b2 [2] f9 b5 [2] e5 9a }

  condition:
    any of them
}