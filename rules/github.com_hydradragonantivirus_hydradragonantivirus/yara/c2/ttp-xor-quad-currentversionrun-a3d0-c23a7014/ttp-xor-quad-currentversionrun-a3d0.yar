rule TTP_XOR_QUAD_CurrentVersionRun_a3d0 {
  strings:
    $key_a3d0 = { f0 bf [2] d4 b1 [2] ff 9d [2] d1 bf [2] c5 a4 [2] ca be [2] d4 a3 [2] d6 a2 [2] cd a4 [2] d1 a3 [2] cd 8c }

  condition:
    any of them
}