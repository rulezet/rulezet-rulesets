rule TTP_XOR_QUAD_CurrentVersionRun_70fc {
  strings:
    $key_70fc = { 23 93 [2] 07 9d [2] 2c b1 [2] 02 93 [2] 16 88 [2] 19 92 [2] 07 8f [2] 05 8e [2] 1e 88 [2] 02 8f [2] 1e a0 }

  condition:
    any of them
}