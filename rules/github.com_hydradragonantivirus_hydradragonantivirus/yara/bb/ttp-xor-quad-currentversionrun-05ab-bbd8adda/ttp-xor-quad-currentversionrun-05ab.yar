rule TTP_XOR_QUAD_CurrentVersionRun_05ab {
  strings:
    $key_05ab = { 56 c4 [2] 72 ca [2] 59 e6 [2] 77 c4 [2] 63 df [2] 6c c5 [2] 72 d8 [2] 70 d9 [2] 6b df [2] 77 d8 [2] 6b f7 }

  condition:
    any of them
}