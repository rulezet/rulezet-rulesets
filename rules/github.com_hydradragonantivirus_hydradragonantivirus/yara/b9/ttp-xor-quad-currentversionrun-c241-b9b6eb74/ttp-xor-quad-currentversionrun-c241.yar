rule TTP_XOR_QUAD_CurrentVersionRun_c241 {
  strings:
    $key_c241 = { 91 2e [2] b5 20 [2] 9e 0c [2] b0 2e [2] a4 35 [2] ab 2f [2] b5 32 [2] b7 33 [2] ac 35 [2] b0 32 [2] ac 1d }

  condition:
    any of them
}