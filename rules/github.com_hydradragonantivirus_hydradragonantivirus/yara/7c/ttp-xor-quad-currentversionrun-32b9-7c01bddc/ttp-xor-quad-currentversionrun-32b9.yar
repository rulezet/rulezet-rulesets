rule TTP_XOR_QUAD_CurrentVersionRun_32b9 {
  strings:
    $key_32b9 = { 61 d6 [2] 45 d8 [2] 6e f4 [2] 40 d6 [2] 54 cd [2] 5b d7 [2] 45 ca [2] 47 cb [2] 5c cd [2] 40 ca [2] 5c e5 }

  condition:
    any of them
}