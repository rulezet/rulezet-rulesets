rule TTP_XOR_QUAD_CurrentVersionRun_c2d0 {
  strings:
    $key_c2d0 = { 91 bf [2] b5 b1 [2] 9e 9d [2] b0 bf [2] a4 a4 [2] ab be [2] b5 a3 [2] b7 a2 [2] ac a4 [2] b0 a3 [2] ac 8c }

  condition:
    any of them
}