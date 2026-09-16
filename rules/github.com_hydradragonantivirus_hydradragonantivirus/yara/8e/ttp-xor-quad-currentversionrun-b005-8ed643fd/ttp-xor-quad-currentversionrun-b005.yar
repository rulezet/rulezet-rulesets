rule TTP_XOR_QUAD_CurrentVersionRun_b005 {
  strings:
    $key_b005 = { e3 6a [2] c7 64 [2] ec 48 [2] c2 6a [2] d6 71 [2] d9 6b [2] c7 76 [2] c5 77 [2] de 71 [2] c2 76 [2] de 59 }

  condition:
    any of them
}