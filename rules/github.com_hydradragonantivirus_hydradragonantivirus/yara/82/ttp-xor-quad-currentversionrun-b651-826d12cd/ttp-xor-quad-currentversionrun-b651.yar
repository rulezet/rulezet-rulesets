rule TTP_XOR_QUAD_CurrentVersionRun_b651 {
  strings:
    $key_b651 = { e5 3e [2] c1 30 [2] ea 1c [2] c4 3e [2] d0 25 [2] df 3f [2] c1 22 [2] c3 23 [2] d8 25 [2] c4 22 [2] d8 0d }

  condition:
    any of them
}