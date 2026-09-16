rule TTP_XOR_QUAD_CurrentVersionRun_c3b9 {
  strings:
    $key_c3b9 = { 90 d6 [2] b4 d8 [2] 9f f4 [2] b1 d6 [2] a5 cd [2] aa d7 [2] b4 ca [2] b6 cb [2] ad cd [2] b1 ca [2] ad e5 }

  condition:
    any of them
}