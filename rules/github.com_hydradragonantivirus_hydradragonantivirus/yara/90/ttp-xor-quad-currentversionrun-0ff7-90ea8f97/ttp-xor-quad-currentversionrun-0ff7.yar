rule TTP_XOR_QUAD_CurrentVersionRun_0ff7 {
  strings:
    $key_0ff7 = { 5c 98 [2] 78 96 [2] 53 ba [2] 7d 98 [2] 69 83 [2] 66 99 [2] 78 84 [2] 7a 85 [2] 61 83 [2] 7d 84 [2] 61 ab }

  condition:
    any of them
}