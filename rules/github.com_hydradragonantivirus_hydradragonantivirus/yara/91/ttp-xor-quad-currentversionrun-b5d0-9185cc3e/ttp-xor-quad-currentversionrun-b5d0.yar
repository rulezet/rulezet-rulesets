rule TTP_XOR_QUAD_CurrentVersionRun_b5d0 {
  strings:
    $key_b5d0 = { e6 bf [2] c2 b1 [2] e9 9d [2] c7 bf [2] d3 a4 [2] dc be [2] c2 a3 [2] c0 a2 [2] db a4 [2] c7 a3 [2] db 8c }

  condition:
    any of them
}