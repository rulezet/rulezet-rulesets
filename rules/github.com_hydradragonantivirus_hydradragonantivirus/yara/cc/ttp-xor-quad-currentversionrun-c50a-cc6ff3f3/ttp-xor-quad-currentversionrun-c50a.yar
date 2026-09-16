rule TTP_XOR_QUAD_CurrentVersionRun_c50a {
  strings:
    $key_c50a = { 96 65 [2] b2 6b [2] 99 47 [2] b7 65 [2] a3 7e [2] ac 64 [2] b2 79 [2] b0 78 [2] ab 7e [2] b7 79 [2] ab 56 }

  condition:
    any of them
}