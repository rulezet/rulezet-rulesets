rule TTP_XOR_QUAD_CurrentVersionRun_d94a {
  strings:
    $key_d94a = { 8a 25 [2] ae 2b [2] 85 07 [2] ab 25 [2] bf 3e [2] b0 24 [2] ae 39 [2] ac 38 [2] b7 3e [2] ab 39 [2] b7 16 }

  condition:
    any of them
}