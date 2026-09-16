rule TTP_XOR_QUAD_CurrentVersionRun_d915 {
  strings:
    $key_d915 = { 8a 7a [2] ae 74 [2] 85 58 [2] ab 7a [2] bf 61 [2] b0 7b [2] ae 66 [2] ac 67 [2] b7 61 [2] ab 66 [2] b7 49 }

  condition:
    any of them
}