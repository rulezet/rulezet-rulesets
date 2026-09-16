rule TTP_XOR_QUAD_CurrentVersionRun_d964 {
  strings:
    $key_d964 = { 8a 0b [2] ae 05 [2] 85 29 [2] ab 0b [2] bf 10 [2] b0 0a [2] ae 17 [2] ac 16 [2] b7 10 [2] ab 17 [2] b7 38 }

  condition:
    any of them
}