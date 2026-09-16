rule TTP_XOR_QUAD_CurrentVersionRun_6dab {
  strings:
    $key_6dab = { 3e c4 [2] 1a ca [2] 31 e6 [2] 1f c4 [2] 0b df [2] 04 c5 [2] 1a d8 [2] 18 d9 [2] 03 df [2] 1f d8 [2] 03 f7 }

  condition:
    any of them
}