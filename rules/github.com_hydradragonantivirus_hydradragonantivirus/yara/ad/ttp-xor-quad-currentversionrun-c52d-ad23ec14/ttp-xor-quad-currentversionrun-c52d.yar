rule TTP_XOR_QUAD_CurrentVersionRun_c52d {
  strings:
    $key_c52d = { 96 42 [2] b2 4c [2] 99 60 [2] b7 42 [2] a3 59 [2] ac 43 [2] b2 5e [2] b0 5f [2] ab 59 [2] b7 5e [2] ab 71 }

  condition:
    any of them
}