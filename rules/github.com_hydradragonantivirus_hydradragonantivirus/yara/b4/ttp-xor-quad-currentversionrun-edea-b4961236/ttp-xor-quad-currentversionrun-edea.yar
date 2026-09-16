rule TTP_XOR_QUAD_CurrentVersionRun_edea {
  strings:
    $key_edea = { be 85 [2] 9a 8b [2] b1 a7 [2] 9f 85 [2] 8b 9e [2] 84 84 [2] 9a 99 [2] 98 98 [2] 83 9e [2] 9f 99 [2] 83 b6 }

  condition:
    any of them
}