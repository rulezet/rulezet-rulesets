rule TTP_XOR_QUAD_CurrentVersionRun_c5f1 {
  strings:
    $key_c5f1 = { 96 9e [2] b2 90 [2] 99 bc [2] b7 9e [2] a3 85 [2] ac 9f [2] b2 82 [2] b0 83 [2] ab 85 [2] b7 82 [2] ab ad }

  condition:
    any of them
}