rule TTP_XOR_QUAD_CurrentVersionRun_b025 {
  strings:
    $key_b025 = { e3 4a [2] c7 44 [2] ec 68 [2] c2 4a [2] d6 51 [2] d9 4b [2] c7 56 [2] c5 57 [2] de 51 [2] c2 56 [2] de 79 }

  condition:
    any of them
}