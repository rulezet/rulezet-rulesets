rule TTP_XOR_QUAD_CurrentVersionRun_06ac {
  strings:
    $key_06ac = { 55 c3 [2] 71 cd [2] 5a e1 [2] 74 c3 [2] 60 d8 [2] 6f c2 [2] 71 df [2] 73 de [2] 68 d8 [2] 74 df [2] 68 f0 }

  condition:
    any of them
}