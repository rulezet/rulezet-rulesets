rule TTP_XOR_QUAD_CurrentVersionRun_7f7f {
  strings:
    $key_7f7f = { 2c 10 [2] 08 1e [2] 23 32 [2] 0d 10 [2] 19 0b [2] 16 11 [2] 08 0c [2] 0a 0d [2] 11 0b [2] 0d 0c [2] 11 23 }

  condition:
    any of them
}