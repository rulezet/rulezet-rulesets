rule TTP_XOR_QUAD_CurrentVersionRun_d9bb {
  strings:
    $key_d9bb = { 8a d4 [2] ae da [2] 85 f6 [2] ab d4 [2] bf cf [2] b0 d5 [2] ae c8 [2] ac c9 [2] b7 cf [2] ab c8 [2] b7 e7 }

  condition:
    any of them
}