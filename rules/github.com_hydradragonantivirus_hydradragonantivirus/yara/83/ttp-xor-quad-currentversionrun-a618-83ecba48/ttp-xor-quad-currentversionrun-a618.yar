rule TTP_XOR_QUAD_CurrentVersionRun_a618 {
  strings:
    $key_a618 = { f5 77 [2] d1 79 [2] fa 55 [2] d4 77 [2] c0 6c [2] cf 76 [2] d1 6b [2] d3 6a [2] c8 6c [2] d4 6b [2] c8 44 }

  condition:
    any of them
}