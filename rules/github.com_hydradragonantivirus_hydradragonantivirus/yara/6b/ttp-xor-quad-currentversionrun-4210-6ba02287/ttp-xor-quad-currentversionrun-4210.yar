rule TTP_XOR_QUAD_CurrentVersionRun_4210 {
  strings:
    $key_4210 = { 11 7f [2] 35 71 [2] 1e 5d [2] 30 7f [2] 24 64 [2] 2b 7e [2] 35 63 [2] 37 62 [2] 2c 64 [2] 30 63 [2] 2c 4c }

  condition:
    any of them
}