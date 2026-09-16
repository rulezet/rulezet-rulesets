rule TTP_XOR_QUAD_CurrentVersionRun_b62f {
  strings:
    $key_b62f = { e5 40 [2] c1 4e [2] ea 62 [2] c4 40 [2] d0 5b [2] df 41 [2] c1 5c [2] c3 5d [2] d8 5b [2] c4 5c [2] d8 73 }

  condition:
    any of them
}