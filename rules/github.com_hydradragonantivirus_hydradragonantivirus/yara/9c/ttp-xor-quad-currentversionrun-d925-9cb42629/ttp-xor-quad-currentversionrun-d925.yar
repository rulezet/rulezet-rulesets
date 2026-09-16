rule TTP_XOR_QUAD_CurrentVersionRun_d925 {
  strings:
    $key_d925 = { 8a 4a [2] ae 44 [2] 85 68 [2] ab 4a [2] bf 51 [2] b0 4b [2] ae 56 [2] ac 57 [2] b7 51 [2] ab 56 [2] b7 79 }

  condition:
    any of them
}