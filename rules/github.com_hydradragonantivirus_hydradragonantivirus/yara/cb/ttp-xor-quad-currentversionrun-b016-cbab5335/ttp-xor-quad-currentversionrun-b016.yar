rule TTP_XOR_QUAD_CurrentVersionRun_b016 {
  strings:
    $key_b016 = { e3 79 [2] c7 77 [2] ec 5b [2] c2 79 [2] d6 62 [2] d9 78 [2] c7 65 [2] c5 64 [2] de 62 [2] c2 65 [2] de 4a }

  condition:
    any of them
}