rule TTP_XOR_QUAD_CurrentVersionRun_c231 {
  strings:
    $key_c231 = { 91 5e [2] b5 50 [2] 9e 7c [2] b0 5e [2] a4 45 [2] ab 5f [2] b5 42 [2] b7 43 [2] ac 45 [2] b0 42 [2] ac 6d }

  condition:
    any of them
}