rule TTP_XOR_QUAD_CurrentVersionRun_c251 {
  strings:
    $key_c251 = { 91 3e [2] b5 30 [2] 9e 1c [2] b0 3e [2] a4 25 [2] ab 3f [2] b5 22 [2] b7 23 [2] ac 25 [2] b0 22 [2] ac 0d }

  condition:
    any of them
}