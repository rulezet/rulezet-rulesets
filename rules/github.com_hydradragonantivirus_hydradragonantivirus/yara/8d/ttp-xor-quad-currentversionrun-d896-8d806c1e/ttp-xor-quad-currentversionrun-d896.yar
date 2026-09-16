rule TTP_XOR_QUAD_CurrentVersionRun_d896 {
  strings:
    $key_d896 = { 8b f9 [2] af f7 [2] 84 db [2] aa f9 [2] be e2 [2] b1 f8 [2] af e5 [2] ad e4 [2] b6 e2 [2] aa e5 [2] b6 ca }

  condition:
    any of them
}