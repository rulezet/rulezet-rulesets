rule TTP_XOR_QUAD_CurrentVersionRun_3de0 {
  strings:
    $key_3de0 = { 6e 8f [2] 4a 81 [2] 61 ad [2] 4f 8f [2] 5b 94 [2] 54 8e [2] 4a 93 [2] 48 92 [2] 53 94 [2] 4f 93 [2] 53 bc }

  condition:
    any of them
}