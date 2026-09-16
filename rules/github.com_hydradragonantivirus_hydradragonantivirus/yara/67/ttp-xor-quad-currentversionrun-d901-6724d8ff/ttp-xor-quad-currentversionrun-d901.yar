rule TTP_XOR_QUAD_CurrentVersionRun_d901 {
  strings:
    $key_d901 = { 8a 6e [2] ae 60 [2] 85 4c [2] ab 6e [2] bf 75 [2] b0 6f [2] ae 72 [2] ac 73 [2] b7 75 [2] ab 72 [2] b7 5d }

  condition:
    any of them
}