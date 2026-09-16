rule TTP_XOR_QUAD_CurrentVersionRun_fef7 {
  strings:
    $key_fef7 = { ad 98 [2] 89 96 [2] a2 ba [2] 8c 98 [2] 98 83 [2] 97 99 [2] 89 84 [2] 8b 85 [2] 90 83 [2] 8c 84 [2] 90 ab }

  condition:
    any of them
}