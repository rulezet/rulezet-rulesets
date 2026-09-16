rule TTP_XOR_QUAD_CurrentVersionRun_c2f1 {
  strings:
    $key_c2f1 = { 91 9e [2] b5 90 [2] 9e bc [2] b0 9e [2] a4 85 [2] ab 9f [2] b5 82 [2] b7 83 [2] ac 85 [2] b0 82 [2] ac ad }

  condition:
    any of them
}