rule TTP_XOR_QUAD_CurrentVersionRun_a306 {
  strings:
    $key_a306 = { f0 69 [2] d4 67 [2] ff 4b [2] d1 69 [2] c5 72 [2] ca 68 [2] d4 75 [2] d6 74 [2] cd 72 [2] d1 75 [2] cd 5a }

  condition:
    any of them
}