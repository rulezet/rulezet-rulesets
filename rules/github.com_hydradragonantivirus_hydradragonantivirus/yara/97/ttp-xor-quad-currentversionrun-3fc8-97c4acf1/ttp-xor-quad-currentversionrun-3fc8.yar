rule TTP_XOR_QUAD_CurrentVersionRun_3fc8 {
  strings:
    $key_3fc8 = { 6c a7 [2] 48 a9 [2] 63 85 [2] 4d a7 [2] 59 bc [2] 56 a6 [2] 48 bb [2] 4a ba [2] 51 bc [2] 4d bb [2] 51 94 }

  condition:
    any of them
}