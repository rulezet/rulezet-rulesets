rule TTP_XOR_QUAD_CurrentVersionRun_efb9 {
  strings:
    $key_efb9 = { bc d6 [2] 98 d8 [2] b3 f4 [2] 9d d6 [2] 89 cd [2] 86 d7 [2] 98 ca [2] 9a cb [2] 81 cd [2] 9d ca [2] 81 e5 }

  condition:
    any of them
}