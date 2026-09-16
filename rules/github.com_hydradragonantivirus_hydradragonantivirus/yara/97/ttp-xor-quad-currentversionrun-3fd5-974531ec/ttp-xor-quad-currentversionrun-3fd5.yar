rule TTP_XOR_QUAD_CurrentVersionRun_3fd5 {
  strings:
    $key_3fd5 = { 6c ba [2] 48 b4 [2] 63 98 [2] 4d ba [2] 59 a1 [2] 56 bb [2] 48 a6 [2] 4a a7 [2] 51 a1 [2] 4d a6 [2] 51 89 }

  condition:
    any of them
}