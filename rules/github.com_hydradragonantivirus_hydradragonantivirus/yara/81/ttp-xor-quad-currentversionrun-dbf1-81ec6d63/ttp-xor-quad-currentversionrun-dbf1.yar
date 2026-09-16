rule TTP_XOR_QUAD_CurrentVersionRun_dbf1 {
  strings:
    $key_dbf1 = { 88 9e [2] ac 90 [2] 87 bc [2] a9 9e [2] bd 85 [2] b2 9f [2] ac 82 [2] ae 83 [2] b5 85 [2] a9 82 [2] b5 ad }

  condition:
    any of them
}