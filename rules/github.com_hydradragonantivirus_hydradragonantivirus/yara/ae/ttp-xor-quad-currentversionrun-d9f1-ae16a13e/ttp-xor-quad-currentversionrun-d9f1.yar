rule TTP_XOR_QUAD_CurrentVersionRun_d9f1 {
  strings:
    $key_d9f1 = { 8a 9e [2] ae 90 [2] 85 bc [2] ab 9e [2] bf 85 [2] b0 9f [2] ae 82 [2] ac 83 [2] b7 85 [2] ab 82 [2] b7 ad }

  condition:
    any of them
}