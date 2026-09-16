rule TTP_XOR_QUAD_CurrentVersionRun_c091 {
  strings:
    $key_c091 = { 93 fe [2] b7 f0 [2] 9c dc [2] b2 fe [2] a6 e5 [2] a9 ff [2] b7 e2 [2] b5 e3 [2] ae e5 [2] b2 e2 [2] ae cd }

  condition:
    any of them
}