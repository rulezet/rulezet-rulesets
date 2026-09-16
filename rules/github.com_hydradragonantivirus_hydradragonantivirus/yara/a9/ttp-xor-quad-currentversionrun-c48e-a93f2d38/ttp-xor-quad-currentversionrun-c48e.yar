rule TTP_XOR_QUAD_CurrentVersionRun_c48e {
  strings:
    $key_c48e = { 97 e1 [2] b3 ef [2] 98 c3 [2] b6 e1 [2] a2 fa [2] ad e0 [2] b3 fd [2] b1 fc [2] aa fa [2] b6 fd [2] aa d2 }

  condition:
    any of them
}