rule TTP_XOR_QUAD_CurrentVersionRun_bfd0 {
  strings:
    $key_bfd0 = { ec bf [2] c8 b1 [2] e3 9d [2] cd bf [2] d9 a4 [2] d6 be [2] c8 a3 [2] ca a2 [2] d1 a4 [2] cd a3 [2] d1 8c }

  condition:
    any of them
}