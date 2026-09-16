rule TTP_XOR_QUAD_CurrentVersionRun_b112 {
  strings:
    $key_b112 = { e2 7d [2] c6 73 [2] ed 5f [2] c3 7d [2] d7 66 [2] d8 7c [2] c6 61 [2] c4 60 [2] df 66 [2] c3 61 [2] df 4e }

  condition:
    any of them
}