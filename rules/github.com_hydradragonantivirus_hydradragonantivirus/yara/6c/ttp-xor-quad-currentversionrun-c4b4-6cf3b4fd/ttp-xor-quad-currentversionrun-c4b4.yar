rule TTP_XOR_QUAD_CurrentVersionRun_c4b4 {
  strings:
    $key_c4b4 = { 97 db [2] b3 d5 [2] 98 f9 [2] b6 db [2] a2 c0 [2] ad da [2] b3 c7 [2] b1 c6 [2] aa c0 [2] b6 c7 [2] aa e8 }

  condition:
    any of them
}