rule TTP_XOR_QUAD_CurrentVersionRun_91d1 {
  strings:
    $key_91d1 = { c2 be [2] e6 b0 [2] cd 9c [2] e3 be [2] f7 a5 [2] f8 bf [2] e6 a2 [2] e4 a3 [2] ff a5 [2] e3 a2 [2] ff 8d }

  condition:
    any of them
}