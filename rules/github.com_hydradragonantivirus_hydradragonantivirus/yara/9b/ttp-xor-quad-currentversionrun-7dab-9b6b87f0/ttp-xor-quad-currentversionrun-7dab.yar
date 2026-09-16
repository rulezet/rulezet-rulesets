rule TTP_XOR_QUAD_CurrentVersionRun_7dab {
  strings:
    $key_7dab = { 2e c4 [2] 0a ca [2] 21 e6 [2] 0f c4 [2] 1b df [2] 14 c5 [2] 0a d8 [2] 08 d9 [2] 13 df [2] 0f d8 [2] 13 f7 }

  condition:
    any of them
}