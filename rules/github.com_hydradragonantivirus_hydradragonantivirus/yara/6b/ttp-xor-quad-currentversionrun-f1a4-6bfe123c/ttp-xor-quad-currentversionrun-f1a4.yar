rule TTP_XOR_QUAD_CurrentVersionRun_f1a4 {
  strings:
    $key_f1a4 = { a2 cb [2] 86 c5 [2] ad e9 [2] 83 cb [2] 97 d0 [2] 98 ca [2] 86 d7 [2] 84 d6 [2] 9f d0 [2] 83 d7 [2] 9f f8 }

  condition:
    any of them
}