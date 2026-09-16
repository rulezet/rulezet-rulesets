rule TTP_XOR_QUAD_CurrentVersionRun_d956 {
  strings:
    $key_d956 = { 8a 39 [2] ae 37 [2] 85 1b [2] ab 39 [2] bf 22 [2] b0 38 [2] ae 25 [2] ac 24 [2] b7 22 [2] ab 25 [2] b7 0a }

  condition:
    any of them
}