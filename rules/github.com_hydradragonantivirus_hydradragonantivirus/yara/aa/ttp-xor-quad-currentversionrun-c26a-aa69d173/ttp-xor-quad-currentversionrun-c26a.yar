rule TTP_XOR_QUAD_CurrentVersionRun_c26a {
  strings:
    $key_c26a = { 91 05 [2] b5 0b [2] 9e 27 [2] b0 05 [2] a4 1e [2] ab 04 [2] b5 19 [2] b7 18 [2] ac 1e [2] b0 19 [2] ac 36 }

  condition:
    any of them
}