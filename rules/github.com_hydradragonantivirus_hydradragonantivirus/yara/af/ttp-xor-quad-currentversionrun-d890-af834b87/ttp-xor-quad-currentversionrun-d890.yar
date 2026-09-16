rule TTP_XOR_QUAD_CurrentVersionRun_d890 {
  strings:
    $key_d890 = { 8b ff [2] af f1 [2] 84 dd [2] aa ff [2] be e4 [2] b1 fe [2] af e3 [2] ad e2 [2] b6 e4 [2] aa e3 [2] b6 cc }

  condition:
    any of them
}