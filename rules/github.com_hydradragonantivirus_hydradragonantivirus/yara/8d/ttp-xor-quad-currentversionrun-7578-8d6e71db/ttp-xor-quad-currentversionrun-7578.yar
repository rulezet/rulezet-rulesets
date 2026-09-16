rule TTP_XOR_QUAD_CurrentVersionRun_7578 {
  strings:
    $key_7578 = { 26 17 [2] 02 19 [2] 29 35 [2] 07 17 [2] 13 0c [2] 1c 16 [2] 02 0b [2] 00 0a [2] 1b 0c [2] 07 0b [2] 1b 24 }

  condition:
    any of them
}