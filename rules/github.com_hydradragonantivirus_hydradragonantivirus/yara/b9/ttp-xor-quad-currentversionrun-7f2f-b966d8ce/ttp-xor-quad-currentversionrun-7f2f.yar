rule TTP_XOR_QUAD_CurrentVersionRun_7f2f {
  strings:
    $key_7f2f = { 2c 40 [2] 08 4e [2] 23 62 [2] 0d 40 [2] 19 5b [2] 16 41 [2] 08 5c [2] 0a 5d [2] 11 5b [2] 0d 5c [2] 11 73 }

  condition:
    any of them
}