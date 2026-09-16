rule TTP_XOR_QUAD_CurrentVersionRun_c520 {
  strings:
    $key_c520 = { 96 4f [2] b2 41 [2] 99 6d [2] b7 4f [2] a3 54 [2] ac 4e [2] b2 53 [2] b0 52 [2] ab 54 [2] b7 53 [2] ab 7c }

  condition:
    any of them
}