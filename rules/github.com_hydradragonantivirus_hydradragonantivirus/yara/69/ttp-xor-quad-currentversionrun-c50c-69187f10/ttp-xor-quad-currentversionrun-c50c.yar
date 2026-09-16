rule TTP_XOR_QUAD_CurrentVersionRun_c50c {
  strings:
    $key_c50c = { 96 63 [2] b2 6d [2] 99 41 [2] b7 63 [2] a3 78 [2] ac 62 [2] b2 7f [2] b0 7e [2] ab 78 [2] b7 7f [2] ab 50 }

  condition:
    any of them
}