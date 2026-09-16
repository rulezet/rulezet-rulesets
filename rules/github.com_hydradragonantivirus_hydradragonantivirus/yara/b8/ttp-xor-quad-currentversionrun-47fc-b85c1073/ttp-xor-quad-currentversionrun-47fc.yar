rule TTP_XOR_QUAD_CurrentVersionRun_47fc {
  strings:
    $key_47fc = { 14 93 [2] 30 9d [2] 1b b1 [2] 35 93 [2] 21 88 [2] 2e 92 [2] 30 8f [2] 32 8e [2] 29 88 [2] 35 8f [2] 29 a0 }

  condition:
    any of them
}