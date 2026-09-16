rule TTP_XOR_QUAD_CurrentVersionRun_c3b8 {
  strings:
    $key_c3b8 = { 90 d7 [2] b4 d9 [2] 9f f5 [2] b1 d7 [2] a5 cc [2] aa d6 [2] b4 cb [2] b6 ca [2] ad cc [2] b1 cb [2] ad e4 }

  condition:
    any of them
}