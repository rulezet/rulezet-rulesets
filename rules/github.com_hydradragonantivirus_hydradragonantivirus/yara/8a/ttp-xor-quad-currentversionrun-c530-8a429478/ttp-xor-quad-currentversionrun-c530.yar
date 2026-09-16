rule TTP_XOR_QUAD_CurrentVersionRun_c530 {
  strings:
    $key_c530 = { 96 5f [2] b2 51 [2] 99 7d [2] b7 5f [2] a3 44 [2] ac 5e [2] b2 43 [2] b0 42 [2] ab 44 [2] b7 43 [2] ab 6c }

  condition:
    any of them
}