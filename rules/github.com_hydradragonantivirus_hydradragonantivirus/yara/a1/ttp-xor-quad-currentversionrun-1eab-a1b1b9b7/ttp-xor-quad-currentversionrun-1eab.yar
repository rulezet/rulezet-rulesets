rule TTP_XOR_QUAD_CurrentVersionRun_1eab {
  strings:
    $key_1eab = { 4d c4 [2] 69 ca [2] 42 e6 [2] 6c c4 [2] 78 df [2] 77 c5 [2] 69 d8 [2] 6b d9 [2] 70 df [2] 6c d8 [2] 70 f7 }

  condition:
    any of them
}