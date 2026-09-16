rule TTP_XOR_QUAD_CurrentVersionRun_bcca {
  strings:
    $key_bcca = { ef a5 [2] cb ab [2] e0 87 [2] ce a5 [2] da be [2] d5 a4 [2] cb b9 [2] c9 b8 [2] d2 be [2] ce b9 [2] d2 96 }

  condition:
    any of them
}