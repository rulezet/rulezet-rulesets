rule TTP_XOR_QUAD_CurrentVersionRun_75ab {
  strings:
    $key_75ab = { 26 c4 [2] 02 ca [2] 29 e6 [2] 07 c4 [2] 13 df [2] 1c c5 [2] 02 d8 [2] 00 d9 [2] 1b df [2] 07 d8 [2] 1b f7 }

  condition:
    any of them
}