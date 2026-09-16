rule TTP_XOR_QUAD_CurrentVersionRun_16b3 {
  strings:
    $key_16b3 = { 45 dc [2] 61 d2 [2] 4a fe [2] 64 dc [2] 70 c7 [2] 7f dd [2] 61 c0 [2] 63 c1 [2] 78 c7 [2] 64 c0 [2] 78 ef }

  condition:
    any of them
}