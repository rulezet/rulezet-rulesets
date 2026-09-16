rule TTP_XOR_QUAD_CurrentVersionRun_7f1f {
  strings:
    $key_7f1f = { 2c 70 [2] 08 7e [2] 23 52 [2] 0d 70 [2] 19 6b [2] 16 71 [2] 08 6c [2] 0a 6d [2] 11 6b [2] 0d 6c [2] 11 43 }

  condition:
    any of them
}