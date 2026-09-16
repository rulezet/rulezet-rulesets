rule TTP_XOR_QUAD_CurrentVersionRun_b17a {
  strings:
    $key_b17a = { e2 15 [2] c6 1b [2] ed 37 [2] c3 15 [2] d7 0e [2] d8 14 [2] c6 09 [2] c4 08 [2] df 0e [2] c3 09 [2] df 26 }

  condition:
    any of them
}