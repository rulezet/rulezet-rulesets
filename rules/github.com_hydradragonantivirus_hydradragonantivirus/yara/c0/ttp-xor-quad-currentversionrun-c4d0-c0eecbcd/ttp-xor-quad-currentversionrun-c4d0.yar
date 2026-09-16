rule TTP_XOR_QUAD_CurrentVersionRun_c4d0 {
  strings:
    $key_c4d0 = { 97 bf [2] b3 b1 [2] 98 9d [2] b6 bf [2] a2 a4 [2] ad be [2] b3 a3 [2] b1 a2 [2] aa a4 [2] b6 a3 [2] aa 8c }

  condition:
    any of them
}