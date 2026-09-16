rule TTP_XOR_QUAD_CurrentVersionRun_2ed5 {
  strings:
    $key_2ed5 = { 7d ba [2] 59 b4 [2] 72 98 [2] 5c ba [2] 48 a1 [2] 47 bb [2] 59 a6 [2] 5b a7 [2] 40 a1 [2] 5c a6 [2] 40 89 }

  condition:
    any of them
}