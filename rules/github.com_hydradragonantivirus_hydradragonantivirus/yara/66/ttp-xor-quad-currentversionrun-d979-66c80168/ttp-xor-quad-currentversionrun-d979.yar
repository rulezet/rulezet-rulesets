rule TTP_XOR_QUAD_CurrentVersionRun_d979 {
  strings:
    $key_d979 = { 8a 16 [2] ae 18 [2] 85 34 [2] ab 16 [2] bf 0d [2] b0 17 [2] ae 0a [2] ac 0b [2] b7 0d [2] ab 0a [2] b7 25 }

  condition:
    any of them
}