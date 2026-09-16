rule TTP_XOR_QUAD_CurrentVersionRun_d94f {
  strings:
    $key_d94f = { 8a 20 [2] ae 2e [2] 85 02 [2] ab 20 [2] bf 3b [2] b0 21 [2] ae 3c [2] ac 3d [2] b7 3b [2] ab 3c [2] b7 13 }

  condition:
    any of them
}