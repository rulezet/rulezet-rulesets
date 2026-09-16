rule TTP_XOR_QUAD_CurrentVersionRun_e8e0 {
  strings:
    $key_e8e0 = { bb 8f [2] 9f 81 [2] b4 ad [2] 9a 8f [2] 8e 94 [2] 81 8e [2] 9f 93 [2] 9d 92 [2] 86 94 [2] 9a 93 [2] 86 bc }

  condition:
    any of them
}