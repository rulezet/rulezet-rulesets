rule TTP_XOR_QUAD_CurrentVersionRun_c5ef {
  strings:
    $key_c5ef = { 96 80 [2] b2 8e [2] 99 a2 [2] b7 80 [2] a3 9b [2] ac 81 [2] b2 9c [2] b0 9d [2] ab 9b [2] b7 9c [2] ab b3 }

  condition:
    any of them
}