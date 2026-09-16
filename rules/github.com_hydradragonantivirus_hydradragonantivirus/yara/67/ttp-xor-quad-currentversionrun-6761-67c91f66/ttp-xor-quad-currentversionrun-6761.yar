rule TTP_XOR_QUAD_CurrentVersionRun_6761 {
  strings:
    $key_6761 = { 34 0e [2] 10 00 [2] 3b 2c [2] 15 0e [2] 01 15 [2] 0e 0f [2] 10 12 [2] 12 13 [2] 09 15 [2] 15 12 [2] 09 3d }

  condition:
    any of them
}