rule TTP_XOR_QUAD_CurrentVersionRun_d977 {
  strings:
    $key_d977 = { 8a 18 [2] ae 16 [2] 85 3a [2] ab 18 [2] bf 03 [2] b0 19 [2] ae 04 [2] ac 05 [2] b7 03 [2] ab 04 [2] b7 2b }

  condition:
    any of them
}