rule TTP_XOR_QUAD_CurrentVersionRun_f691 {
  strings:
    $key_f691 = { a5 fe [2] 81 f0 [2] aa dc [2] 84 fe [2] 90 e5 [2] 9f ff [2] 81 e2 [2] 83 e3 [2] 98 e5 [2] 84 e2 [2] 98 cd }

  condition:
    any of them
}