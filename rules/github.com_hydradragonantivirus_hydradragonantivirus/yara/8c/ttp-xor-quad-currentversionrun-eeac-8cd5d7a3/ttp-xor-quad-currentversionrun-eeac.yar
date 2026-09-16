rule TTP_XOR_QUAD_CurrentVersionRun_eeac {
  strings:
    $key_eeac = { bd c3 [2] 99 cd [2] b2 e1 [2] 9c c3 [2] 88 d8 [2] 87 c2 [2] 99 df [2] 9b de [2] 80 d8 [2] 9c df [2] 80 f0 }

  condition:
    any of them
}