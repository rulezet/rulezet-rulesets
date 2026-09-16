rule TTP_XOR_QUAD_CurrentVersionRun_3dab {
  strings:
    $key_3dab = { 6e c4 [2] 4a ca [2] 61 e6 [2] 4f c4 [2] 5b df [2] 54 c5 [2] 4a d8 [2] 48 d9 [2] 53 df [2] 4f d8 [2] 53 f7 }

  condition:
    any of them
}