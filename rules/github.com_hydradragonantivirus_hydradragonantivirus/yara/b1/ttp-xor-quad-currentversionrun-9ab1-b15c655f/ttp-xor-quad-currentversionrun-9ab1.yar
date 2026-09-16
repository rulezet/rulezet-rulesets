rule TTP_XOR_QUAD_CurrentVersionRun_9ab1 {
  strings:
    $key_9ab1 = { c9 de [2] ed d0 [2] c6 fc [2] e8 de [2] fc c5 [2] f3 df [2] ed c2 [2] ef c3 [2] f4 c5 [2] e8 c2 [2] f4 ed }

  condition:
    any of them
}