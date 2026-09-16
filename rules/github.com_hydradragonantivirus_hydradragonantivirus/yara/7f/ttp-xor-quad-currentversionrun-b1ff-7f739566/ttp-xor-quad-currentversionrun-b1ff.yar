rule TTP_XOR_QUAD_CurrentVersionRun_b1ff {
  strings:
    $key_b1ff = { e2 90 [2] c6 9e [2] ed b2 [2] c3 90 [2] d7 8b [2] d8 91 [2] c6 8c [2] c4 8d [2] df 8b [2] c3 8c [2] df a3 }

  condition:
    any of them
}