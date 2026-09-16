rule TTP_XOR_QUAD_CurrentVersionRun_b8d1 {
  strings:
    $key_b8d1 = { eb be [2] cf b0 [2] e4 9c [2] ca be [2] de a5 [2] d1 bf [2] cf a2 [2] cd a3 [2] d6 a5 [2] ca a2 [2] d6 8d }

  condition:
    any of them
}