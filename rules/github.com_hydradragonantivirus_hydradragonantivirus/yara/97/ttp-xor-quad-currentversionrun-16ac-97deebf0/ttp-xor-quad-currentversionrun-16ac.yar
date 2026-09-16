rule TTP_XOR_QUAD_CurrentVersionRun_16ac {
  strings:
    $key_16ac = { 45 c3 [2] 61 cd [2] 4a e1 [2] 64 c3 [2] 70 d8 [2] 7f c2 [2] 61 df [2] 63 de [2] 78 d8 [2] 64 df [2] 78 f0 }

  condition:
    any of them
}