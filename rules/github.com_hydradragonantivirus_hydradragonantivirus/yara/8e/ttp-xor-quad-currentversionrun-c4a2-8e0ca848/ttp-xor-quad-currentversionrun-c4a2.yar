rule TTP_XOR_QUAD_CurrentVersionRun_c4a2 {
  strings:
    $key_c4a2 = { 97 cd [2] b3 c3 [2] 98 ef [2] b6 cd [2] a2 d6 [2] ad cc [2] b3 d1 [2] b1 d0 [2] aa d6 [2] b6 d1 [2] aa fe }

  condition:
    any of them
}