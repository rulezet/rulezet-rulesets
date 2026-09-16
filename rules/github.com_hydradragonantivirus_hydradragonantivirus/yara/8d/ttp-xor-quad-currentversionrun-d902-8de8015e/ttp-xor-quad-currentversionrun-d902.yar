rule TTP_XOR_QUAD_CurrentVersionRun_d902 {
  strings:
    $key_d902 = { 8a 6d [2] ae 63 [2] 85 4f [2] ab 6d [2] bf 76 [2] b0 6c [2] ae 71 [2] ac 70 [2] b7 76 [2] ab 71 [2] b7 5e }

  condition:
    any of them
}