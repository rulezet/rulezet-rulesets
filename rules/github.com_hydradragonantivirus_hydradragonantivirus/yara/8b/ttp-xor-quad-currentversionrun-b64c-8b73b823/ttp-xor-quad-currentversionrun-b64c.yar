rule TTP_XOR_QUAD_CurrentVersionRun_b64c {
  strings:
    $key_b64c = { e5 23 [2] c1 2d [2] ea 01 [2] c4 23 [2] d0 38 [2] df 22 [2] c1 3f [2] c3 3e [2] d8 38 [2] c4 3f [2] d8 10 }

  condition:
    any of them
}