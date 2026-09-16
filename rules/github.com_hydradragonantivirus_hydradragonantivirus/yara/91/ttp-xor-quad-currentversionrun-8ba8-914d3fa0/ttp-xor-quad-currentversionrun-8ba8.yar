rule TTP_XOR_QUAD_CurrentVersionRun_8ba8 {
  strings:
    $key_8ba8 = { d8 c7 [2] fc c9 [2] d7 e5 [2] f9 c7 [2] ed dc [2] e2 c6 [2] fc db [2] fe da [2] e5 dc [2] f9 db [2] e5 f4 }

  condition:
    any of them
}