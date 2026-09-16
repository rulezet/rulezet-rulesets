rule TTP_XOR_QUAD_CurrentVersionRun_eab9 {
  strings:
    $key_eab9 = { b9 d6 [2] 9d d8 [2] b6 f4 [2] 98 d6 [2] 8c cd [2] 83 d7 [2] 9d ca [2] 9f cb [2] 84 cd [2] 98 ca [2] 84 e5 }

  condition:
    any of them
}