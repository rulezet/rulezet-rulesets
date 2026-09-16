rule TTP_XOR_QUAD_CurrentVersionRun_8bd7 {
  strings:
    $key_8bd7 = { d8 b8 [2] fc b6 [2] d7 9a [2] f9 b8 [2] ed a3 [2] e2 b9 [2] fc a4 [2] fe a5 [2] e5 a3 [2] f9 a4 [2] e5 8b }

  condition:
    any of them
}