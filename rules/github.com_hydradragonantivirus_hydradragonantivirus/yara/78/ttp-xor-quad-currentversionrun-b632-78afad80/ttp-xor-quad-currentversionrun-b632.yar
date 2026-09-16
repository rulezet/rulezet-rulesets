rule TTP_XOR_QUAD_CurrentVersionRun_b632 {
  strings:
    $key_b632 = { e5 5d [2] c1 53 [2] ea 7f [2] c4 5d [2] d0 46 [2] df 5c [2] c1 41 [2] c3 40 [2] d8 46 [2] c4 41 [2] d8 6e }

  condition:
    any of them
}