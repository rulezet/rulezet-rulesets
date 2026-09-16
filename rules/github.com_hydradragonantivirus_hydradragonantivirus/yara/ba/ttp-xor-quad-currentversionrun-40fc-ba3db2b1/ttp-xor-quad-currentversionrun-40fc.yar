rule TTP_XOR_QUAD_CurrentVersionRun_40fc {
  strings:
    $key_40fc = { 13 93 [2] 37 9d [2] 1c b1 [2] 32 93 [2] 26 88 [2] 29 92 [2] 37 8f [2] 35 8e [2] 2e 88 [2] 32 8f [2] 2e a0 }

  condition:
    any of them
}