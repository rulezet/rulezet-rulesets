rule TTP_XOR_QUAD_CurrentVersionRun_c2ef {
  strings:
    $key_c2ef = { 91 80 [2] b5 8e [2] 9e a2 [2] b0 80 [2] a4 9b [2] ab 81 [2] b5 9c [2] b7 9d [2] ac 9b [2] b0 9c [2] ac b3 }

  condition:
    any of them
}