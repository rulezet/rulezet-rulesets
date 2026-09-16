rule TTP_XOR_QUAD_CurrentVersionRun_452f {
  strings:
    $key_452f = { 16 40 [2] 32 4e [2] 19 62 [2] 37 40 [2] 23 5b [2] 2c 41 [2] 32 5c [2] 30 5d [2] 2b 5b [2] 37 5c [2] 2b 73 }

  condition:
    any of them
}