rule TTP_XOR_QUAD_CurrentVersionRun_d9e0 {
  strings:
    $key_d9e0 = { 8a 8f [2] ae 81 [2] 85 ad [2] ab 8f [2] bf 94 [2] b0 8e [2] ae 93 [2] ac 92 [2] b7 94 [2] ab 93 [2] b7 bc }

  condition:
    any of them
}