rule TTP_XOR_QUAD_CurrentVersionRun_d932 {
  strings:
    $key_d932 = { 8a 5d [2] ae 53 [2] 85 7f [2] ab 5d [2] bf 46 [2] b0 5c [2] ae 41 [2] ac 40 [2] b7 46 [2] ab 41 [2] b7 6e }

  condition:
    any of them
}