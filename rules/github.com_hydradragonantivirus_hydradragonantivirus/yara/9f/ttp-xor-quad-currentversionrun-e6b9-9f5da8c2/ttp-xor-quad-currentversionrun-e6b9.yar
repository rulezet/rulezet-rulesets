rule TTP_XOR_QUAD_CurrentVersionRun_e6b9 {
  strings:
    $key_e6b9 = { b5 d6 [2] 91 d8 [2] ba f4 [2] 94 d6 [2] 80 cd [2] 8f d7 [2] 91 ca [2] 93 cb [2] 88 cd [2] 94 ca [2] 88 e5 }

  condition:
    any of them
}