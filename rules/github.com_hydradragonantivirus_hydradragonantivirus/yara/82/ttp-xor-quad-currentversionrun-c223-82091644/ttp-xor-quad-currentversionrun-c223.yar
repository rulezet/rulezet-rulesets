rule TTP_XOR_QUAD_CurrentVersionRun_c223 {
  strings:
    $key_c223 = { 91 4c [2] b5 42 [2] 9e 6e [2] b0 4c [2] a4 57 [2] ab 4d [2] b5 50 [2] b7 51 [2] ac 57 [2] b0 50 [2] ac 7f }

  condition:
    any of them
}