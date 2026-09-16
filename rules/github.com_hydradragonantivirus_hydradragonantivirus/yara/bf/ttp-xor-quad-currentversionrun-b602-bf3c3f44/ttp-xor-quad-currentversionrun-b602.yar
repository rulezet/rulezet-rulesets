rule TTP_XOR_QUAD_CurrentVersionRun_b602 {
  strings:
    $key_b602 = { e5 6d [2] c1 63 [2] ea 4f [2] c4 6d [2] d0 76 [2] df 6c [2] c1 71 [2] c3 70 [2] d8 76 [2] c4 71 [2] d8 5e }

  condition:
    any of them
}