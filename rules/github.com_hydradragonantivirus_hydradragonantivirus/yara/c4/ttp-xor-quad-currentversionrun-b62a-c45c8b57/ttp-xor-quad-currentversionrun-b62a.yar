rule TTP_XOR_QUAD_CurrentVersionRun_b62a {
  strings:
    $key_b62a = { e5 45 [2] c1 4b [2] ea 67 [2] c4 45 [2] d0 5e [2] df 44 [2] c1 59 [2] c3 58 [2] d8 5e [2] c4 59 [2] d8 76 }

  condition:
    any of them
}