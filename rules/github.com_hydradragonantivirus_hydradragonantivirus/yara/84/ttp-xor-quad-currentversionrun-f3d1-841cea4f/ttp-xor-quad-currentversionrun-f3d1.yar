rule TTP_XOR_QUAD_CurrentVersionRun_f3d1 {
  strings:
    $key_f3d1 = { a0 be [2] 84 b0 [2] af 9c [2] 81 be [2] 95 a5 [2] 9a bf [2] 84 a2 [2] 86 a3 [2] 9d a5 [2] 81 a2 [2] 9d 8d }

  condition:
    any of them
}