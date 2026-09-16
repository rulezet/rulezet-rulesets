rule TTP_XOR_QUAD_CurrentVersionRun_5845 {
  strings:
    $key_5845 = { 0b 2a [2] 2f 24 [2] 04 08 [2] 2a 2a [2] 3e 31 [2] 31 2b [2] 2f 36 [2] 2d 37 [2] 36 31 [2] 2a 36 [2] 36 19 }

  condition:
    any of them
}