rule TTP_XOR_QUAD_CurrentVersionRun_a053 {
  strings:
    $key_a053 = { f3 3c [2] d7 32 [2] fc 1e [2] d2 3c [2] c6 27 [2] c9 3d [2] d7 20 [2] d5 21 [2] ce 27 [2] d2 20 [2] ce 0f }

  condition:
    any of them
}