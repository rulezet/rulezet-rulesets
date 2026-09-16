rule TTP_XOR_QUAD_CurrentVersionRun_d090 {
  strings:
    $key_d090 = { 83 ff [2] a7 f1 [2] 8c dd [2] a2 ff [2] b6 e4 [2] b9 fe [2] a7 e3 [2] a5 e2 [2] be e4 [2] a2 e3 [2] be cc }

  condition:
    any of them
}