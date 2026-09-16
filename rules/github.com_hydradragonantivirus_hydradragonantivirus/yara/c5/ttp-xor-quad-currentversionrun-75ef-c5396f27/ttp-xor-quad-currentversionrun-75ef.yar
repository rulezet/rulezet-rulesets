rule TTP_XOR_QUAD_CurrentVersionRun_75ef {
  strings:
    $key_75ef = { 26 80 [2] 02 8e [2] 29 a2 [2] 07 80 [2] 13 9b [2] 1c 81 [2] 02 9c [2] 00 9d [2] 1b 9b [2] 07 9c [2] 1b b3 }

  condition:
    any of them
}