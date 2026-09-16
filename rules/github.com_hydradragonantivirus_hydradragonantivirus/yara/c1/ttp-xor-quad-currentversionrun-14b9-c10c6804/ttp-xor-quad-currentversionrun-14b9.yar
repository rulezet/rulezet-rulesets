rule TTP_XOR_QUAD_CurrentVersionRun_14b9 {
  strings:
    $key_14b9 = { 47 d6 [2] 63 d8 [2] 48 f4 [2] 66 d6 [2] 72 cd [2] 7d d7 [2] 63 ca [2] 61 cb [2] 7a cd [2] 66 ca [2] 7a e5 }

  condition:
    any of them
}