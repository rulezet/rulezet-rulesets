rule TTP_XOR_QUAD_CurrentVersionRun_b616 {
  strings:
    $key_b616 = { e5 79 [2] c1 77 [2] ea 5b [2] c4 79 [2] d0 62 [2] df 78 [2] c1 65 [2] c3 64 [2] d8 62 [2] c4 65 [2] d8 4a }

  condition:
    any of them
}