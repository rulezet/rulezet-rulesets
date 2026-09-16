rule TTP_XOR_QUAD_CurrentVersionRun_b1f2 {
  strings:
    $key_b1f2 = { e2 9d [2] c6 93 [2] ed bf [2] c3 9d [2] d7 86 [2] d8 9c [2] c6 81 [2] c4 80 [2] df 86 [2] c3 81 [2] df ae }

  condition:
    any of them
}