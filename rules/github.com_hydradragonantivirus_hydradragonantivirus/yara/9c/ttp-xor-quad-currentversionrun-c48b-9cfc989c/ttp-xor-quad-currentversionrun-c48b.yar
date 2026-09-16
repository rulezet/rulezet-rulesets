rule TTP_XOR_QUAD_CurrentVersionRun_c48b {
  strings:
    $key_c48b = { 97 e4 [2] b3 ea [2] 98 c6 [2] b6 e4 [2] a2 ff [2] ad e5 [2] b3 f8 [2] b1 f9 [2] aa ff [2] b6 f8 [2] aa d7 }

  condition:
    any of them
}