rule TTP_XOR_QUAD_CurrentVersionRun_e3f7 {
  strings:
    $key_e3f7 = { b0 98 [2] 94 96 [2] bf ba [2] 91 98 [2] 85 83 [2] 8a 99 [2] 94 84 [2] 96 85 [2] 8d 83 [2] 91 84 [2] 8d ab }

  condition:
    any of them
}