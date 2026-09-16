rule TTP_XOR_QUAD_CurrentVersionRun_13b9 {
  strings:
    $key_13b9 = { 40 d6 [2] 64 d8 [2] 4f f4 [2] 61 d6 [2] 75 cd [2] 7a d7 [2] 64 ca [2] 66 cb [2] 7d cd [2] 61 ca [2] 7d e5 }

  condition:
    any of them
}