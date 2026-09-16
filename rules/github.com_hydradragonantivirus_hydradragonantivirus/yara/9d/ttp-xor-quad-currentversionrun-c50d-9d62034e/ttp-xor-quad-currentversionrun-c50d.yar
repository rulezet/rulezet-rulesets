rule TTP_XOR_QUAD_CurrentVersionRun_c50d {
  strings:
    $key_c50d = { 96 62 [2] b2 6c [2] 99 40 [2] b7 62 [2] a3 79 [2] ac 63 [2] b2 7e [2] b0 7f [2] ab 79 [2] b7 7e [2] ab 51 }

  condition:
    any of them
}