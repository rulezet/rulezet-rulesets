rule TTP_XOR_QUAD_CurrentVersionRun_c533 {
  strings:
    $key_c533 = { 96 5c [2] b2 52 [2] 99 7e [2] b7 5c [2] a3 47 [2] ac 5d [2] b2 40 [2] b0 41 [2] ab 47 [2] b7 40 [2] ab 6f }

  condition:
    any of them
}