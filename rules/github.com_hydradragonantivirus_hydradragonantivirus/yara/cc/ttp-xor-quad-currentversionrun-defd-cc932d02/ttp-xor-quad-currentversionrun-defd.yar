rule TTP_XOR_QUAD_CurrentVersionRun_defd {
  strings:
    $key_defd = { 8d 92 [2] a9 9c [2] 82 b0 [2] ac 92 [2] b8 89 [2] b7 93 [2] a9 8e [2] ab 8f [2] b0 89 [2] ac 8e [2] b0 a1 }

  condition:
    any of them
}