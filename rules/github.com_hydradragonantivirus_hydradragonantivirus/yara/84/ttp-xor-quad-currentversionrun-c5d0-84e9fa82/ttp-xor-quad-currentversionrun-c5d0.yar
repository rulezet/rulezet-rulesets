rule TTP_XOR_QUAD_CurrentVersionRun_c5d0 {
  strings:
    $key_c5d0 = { 96 bf [2] b2 b1 [2] 99 9d [2] b7 bf [2] a3 a4 [2] ac be [2] b2 a3 [2] b0 a2 [2] ab a4 [2] b7 a3 [2] ab 8c }

  condition:
    any of them
}