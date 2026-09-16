rule TTP_XOR_QUAD_CurrentVersionRun_b14f {
  strings:
    $key_b14f = { e2 20 [2] c6 2e [2] ed 02 [2] c3 20 [2] d7 3b [2] d8 21 [2] c6 3c [2] c4 3d [2] df 3b [2] c3 3c [2] df 13 }

  condition:
    any of them
}