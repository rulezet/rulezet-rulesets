rule TTP_XOR_QUAD_CurrentVersionRun_d905 {
  strings:
    $key_d905 = { 8a 6a [2] ae 64 [2] 85 48 [2] ab 6a [2] bf 71 [2] b0 6b [2] ae 76 [2] ac 77 [2] b7 71 [2] ab 76 [2] b7 59 }

  condition:
    any of them
}