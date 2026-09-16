rule TTP_XOR_QUAD_CurrentVersionRun_d92f {
  strings:
    $key_d92f = { 8a 40 [2] ae 4e [2] 85 62 [2] ab 40 [2] bf 5b [2] b0 41 [2] ae 5c [2] ac 5d [2] b7 5b [2] ab 5c [2] b7 73 }

  condition:
    any of them
}