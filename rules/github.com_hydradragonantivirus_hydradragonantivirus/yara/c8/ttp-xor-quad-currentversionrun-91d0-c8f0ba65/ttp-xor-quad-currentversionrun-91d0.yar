rule TTP_XOR_QUAD_CurrentVersionRun_91d0 {
  strings:
    $key_91d0 = { c2 bf [2] e6 b1 [2] cd 9d [2] e3 bf [2] f7 a4 [2] f8 be [2] e6 a3 [2] e4 a2 [2] ff a4 [2] e3 a3 [2] ff 8c }

  condition:
    any of them
}