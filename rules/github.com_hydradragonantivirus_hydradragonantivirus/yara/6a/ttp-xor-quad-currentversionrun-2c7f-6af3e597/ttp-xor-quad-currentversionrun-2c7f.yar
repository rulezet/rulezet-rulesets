rule TTP_XOR_QUAD_CurrentVersionRun_2c7f {
  strings:
    $key_2c7f = { 7f 10 [2] 5b 1e [2] 70 32 [2] 5e 10 [2] 4a 0b [2] 45 11 [2] 5b 0c [2] 59 0d [2] 42 0b [2] 5e 0c [2] 42 23 }

  condition:
    any of them
}