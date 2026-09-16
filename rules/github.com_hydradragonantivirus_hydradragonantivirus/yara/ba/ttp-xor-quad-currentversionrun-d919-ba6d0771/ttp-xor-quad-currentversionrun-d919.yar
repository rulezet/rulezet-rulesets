rule TTP_XOR_QUAD_CurrentVersionRun_d919 {
  strings:
    $key_d919 = { 8a 76 [2] ae 78 [2] 85 54 [2] ab 76 [2] bf 6d [2] b0 77 [2] ae 6a [2] ac 6b [2] b7 6d [2] ab 6a [2] b7 45 }

  condition:
    any of them
}