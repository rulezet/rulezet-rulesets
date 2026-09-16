rule TTP_XOR_QUAD_CurrentVersionRun_b618 {
  strings:
    $key_b618 = { e5 77 [2] c1 79 [2] ea 55 [2] c4 77 [2] d0 6c [2] df 76 [2] c1 6b [2] c3 6a [2] d8 6c [2] c4 6b [2] d8 44 }

  condition:
    any of them
}