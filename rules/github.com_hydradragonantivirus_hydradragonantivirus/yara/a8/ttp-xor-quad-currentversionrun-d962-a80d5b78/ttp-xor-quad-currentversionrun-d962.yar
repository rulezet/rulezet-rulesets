rule TTP_XOR_QUAD_CurrentVersionRun_d962 {
  strings:
    $key_d962 = { 8a 0d [2] ae 03 [2] 85 2f [2] ab 0d [2] bf 16 [2] b0 0c [2] ae 11 [2] ac 10 [2] b7 16 [2] ab 11 [2] b7 3e }

  condition:
    any of them
}