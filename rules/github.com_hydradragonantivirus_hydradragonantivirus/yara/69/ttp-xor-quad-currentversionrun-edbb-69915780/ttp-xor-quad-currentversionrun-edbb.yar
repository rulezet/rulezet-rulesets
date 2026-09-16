rule TTP_XOR_QUAD_CurrentVersionRun_edbb {
  strings:
    $key_edbb = { be d4 [2] 9a da [2] b1 f6 [2] 9f d4 [2] 8b cf [2] 84 d5 [2] 9a c8 [2] 98 c9 [2] 83 cf [2] 9f c8 [2] 83 e7 }

  condition:
    any of them
}