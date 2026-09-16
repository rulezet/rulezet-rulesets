rule TTP_XOR_QUAD_CurrentVersionRun_b671 {
  strings:
    $key_b671 = { e5 1e [2] c1 10 [2] ea 3c [2] c4 1e [2] d0 05 [2] df 1f [2] c1 02 [2] c3 03 [2] d8 05 [2] c4 02 [2] d8 2d }

  condition:
    any of them
}