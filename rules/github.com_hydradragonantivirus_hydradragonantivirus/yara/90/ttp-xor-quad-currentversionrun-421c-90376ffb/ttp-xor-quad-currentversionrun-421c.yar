rule TTP_XOR_QUAD_CurrentVersionRun_421c {
  strings:
    $key_421c = { 11 73 [2] 35 7d [2] 1e 51 [2] 30 73 [2] 24 68 [2] 2b 72 [2] 35 6f [2] 37 6e [2] 2c 68 [2] 30 6f [2] 2c 40 }

  condition:
    any of them
}