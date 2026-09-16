rule TTP_XOR_QUAD_CurrentVersionRun_b8af {
  strings:
    $key_b8af = { eb c0 [2] cf ce [2] e4 e2 [2] ca c0 [2] de db [2] d1 c1 [2] cf dc [2] cd dd [2] d6 db [2] ca dc [2] d6 f3 }

  condition:
    any of them
}