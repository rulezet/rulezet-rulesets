rule TTP_XOR_QUAD_CurrentVersionRun_def1 {
  strings:
    $key_def1 = { 8d 9e [2] a9 90 [2] 82 bc [2] ac 9e [2] b8 85 [2] b7 9f [2] a9 82 [2] ab 83 [2] b0 85 [2] ac 82 [2] b0 ad }

  condition:
    any of them
}