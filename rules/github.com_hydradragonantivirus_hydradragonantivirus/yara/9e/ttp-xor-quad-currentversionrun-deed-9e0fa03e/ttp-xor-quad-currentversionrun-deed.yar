rule TTP_XOR_QUAD_CurrentVersionRun_deed {
  strings:
    $key_deed = { 8d 82 [2] a9 8c [2] 82 a0 [2] ac 82 [2] b8 99 [2] b7 83 [2] a9 9e [2] ab 9f [2] b0 99 [2] ac 9e [2] b0 b1 }

  condition:
    any of them
}