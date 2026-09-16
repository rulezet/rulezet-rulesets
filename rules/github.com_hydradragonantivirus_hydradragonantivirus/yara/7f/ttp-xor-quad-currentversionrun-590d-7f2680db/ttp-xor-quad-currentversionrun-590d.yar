rule TTP_XOR_QUAD_CurrentVersionRun_590d {
  strings:
    $key_590d = { 0a 62 [2] 2e 6c [2] 05 40 [2] 2b 62 [2] 3f 79 [2] 30 63 [2] 2e 7e [2] 2c 7f [2] 37 79 [2] 2b 7e [2] 37 51 }

  condition:
    any of them
}