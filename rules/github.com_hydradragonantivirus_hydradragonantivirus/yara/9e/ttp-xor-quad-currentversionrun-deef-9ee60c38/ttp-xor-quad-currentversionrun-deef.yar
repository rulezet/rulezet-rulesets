rule TTP_XOR_QUAD_CurrentVersionRun_deef {
  strings:
    $key_deef = { 8d 80 [2] a9 8e [2] 82 a2 [2] ac 80 [2] b8 9b [2] b7 81 [2] a9 9c [2] ab 9d [2] b0 9b [2] ac 9c [2] b0 b3 }

  condition:
    any of them
}