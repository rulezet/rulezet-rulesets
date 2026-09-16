rule TTP_XOR_QUAD_CurrentVersionRun_deec {
  strings:
    $key_deec = { 8d 83 [2] a9 8d [2] 82 a1 [2] ac 83 [2] b8 98 [2] b7 82 [2] a9 9f [2] ab 9e [2] b0 98 [2] ac 9f [2] b0 b0 }

  condition:
    any of them
}