rule TTP_XOR_QUAD_CurrentVersionRun_d90d {
  strings:
    $key_d90d = { 8a 62 [2] ae 6c [2] 85 40 [2] ab 62 [2] bf 79 [2] b0 63 [2] ae 7e [2] ac 7f [2] b7 79 [2] ab 7e [2] b7 51 }

  condition:
    any of them
}