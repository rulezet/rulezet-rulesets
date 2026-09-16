rule TTP_XOR_QUAD_CurrentVersionRun_c48a {
  strings:
    $key_c48a = { 97 e5 [2] b3 eb [2] 98 c7 [2] b6 e5 [2] a2 fe [2] ad e4 [2] b3 f9 [2] b1 f8 [2] aa fe [2] b6 f9 [2] aa d6 }

  condition:
    any of them
}