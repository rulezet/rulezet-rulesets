rule TTP_XOR_QUAD_CurrentVersionRun_6245 {
  strings:
    $key_6245 = { 31 2a [2] 15 24 [2] 3e 08 [2] 10 2a [2] 04 31 [2] 0b 2b [2] 15 36 [2] 17 37 [2] 0c 31 [2] 10 36 [2] 0c 19 }

  condition:
    any of them
}