rule TTP_XOR_QUAD_CurrentVersionRun_7f3f {
  strings:
    $key_7f3f = { 2c 50 [2] 08 5e [2] 23 72 [2] 0d 50 [2] 19 4b [2] 16 51 [2] 08 4c [2] 0a 4d [2] 11 4b [2] 0d 4c [2] 11 63 }

  condition:
    any of them
}