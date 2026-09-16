rule TTP_XOR_QUAD_CurrentVersionRun_05d0 {
  strings:
    $key_05d0 = { 56 bf [2] 72 b1 [2] 59 9d [2] 77 bf [2] 63 a4 [2] 6c be [2] 72 a3 [2] 70 a2 [2] 6b a4 [2] 77 a3 [2] 6b 8c }

  condition:
    any of them
}