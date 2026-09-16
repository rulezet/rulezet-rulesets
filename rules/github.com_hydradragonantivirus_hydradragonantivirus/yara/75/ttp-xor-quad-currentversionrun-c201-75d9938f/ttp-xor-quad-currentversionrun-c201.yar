rule TTP_XOR_QUAD_CurrentVersionRun_c201 {
  strings:
    $key_c201 = { 91 6e [2] b5 60 [2] 9e 4c [2] b0 6e [2] a4 75 [2] ab 6f [2] b5 72 [2] b7 73 [2] ac 75 [2] b0 72 [2] ac 5d }

  condition:
    any of them
}