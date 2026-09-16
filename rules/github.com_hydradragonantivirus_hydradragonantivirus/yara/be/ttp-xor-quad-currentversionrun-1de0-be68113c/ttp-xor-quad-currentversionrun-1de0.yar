rule TTP_XOR_QUAD_CurrentVersionRun_1de0 {
  strings:
    $key_1de0 = { 4e 8f [2] 6a 81 [2] 41 ad [2] 6f 8f [2] 7b 94 [2] 74 8e [2] 6a 93 [2] 68 92 [2] 73 94 [2] 6f 93 [2] 73 bc }

  condition:
    any of them
}