rule TTP_XOR_QUAD_CurrentVersionRun_75ac {
  strings:
    $key_75ac = { 26 c3 [2] 02 cd [2] 29 e1 [2] 07 c3 [2] 13 d8 [2] 1c c2 [2] 02 df [2] 00 de [2] 1b d8 [2] 07 df [2] 1b f0 }

  condition:
    any of them
}