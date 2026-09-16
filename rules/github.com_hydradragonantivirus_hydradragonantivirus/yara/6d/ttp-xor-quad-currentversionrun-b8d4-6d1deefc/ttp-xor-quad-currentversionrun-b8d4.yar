rule TTP_XOR_QUAD_CurrentVersionRun_b8d4 {
  strings:
    $key_b8d4 = { eb bb [2] cf b5 [2] e4 99 [2] ca bb [2] de a0 [2] d1 ba [2] cf a7 [2] cd a6 [2] d6 a0 [2] ca a7 [2] d6 88 }

  condition:
    any of them
}