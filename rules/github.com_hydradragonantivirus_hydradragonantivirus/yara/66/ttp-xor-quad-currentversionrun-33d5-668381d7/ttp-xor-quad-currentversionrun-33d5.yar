rule TTP_XOR_QUAD_CurrentVersionRun_33d5 {
  strings:
    $key_33d5 = { 60 ba [2] 44 b4 [2] 6f 98 [2] 41 ba [2] 55 a1 [2] 5a bb [2] 44 a6 [2] 46 a7 [2] 5d a1 [2] 41 a6 [2] 5d 89 }

  condition:
    any of them
}