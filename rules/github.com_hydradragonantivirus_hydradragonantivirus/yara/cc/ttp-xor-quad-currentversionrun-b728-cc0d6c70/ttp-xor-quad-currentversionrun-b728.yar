rule TTP_XOR_QUAD_CurrentVersionRun_b728 {
  strings:
    $key_b728 = { e4 47 [2] c0 49 [2] eb 65 [2] c5 47 [2] d1 5c [2] de 46 [2] c0 5b [2] c2 5a [2] d9 5c [2] c5 5b [2] d9 74 }

  condition:
    any of them
}