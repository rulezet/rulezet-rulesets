rule TTP_XOR_QUAD_CurrentVersionRun_34b9 {
  strings:
    $key_34b9 = { 67 d6 [2] 43 d8 [2] 68 f4 [2] 46 d6 [2] 52 cd [2] 5d d7 [2] 43 ca [2] 41 cb [2] 5a cd [2] 46 ca [2] 5a e5 }

  condition:
    any of them
}