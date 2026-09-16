rule TTP_XOR_QUAD_CurrentVersionRun_5044 {
  strings:
    $key_5044 = { 03 2b [2] 27 25 [2] 0c 09 [2] 22 2b [2] 36 30 [2] 39 2a [2] 27 37 [2] 25 36 [2] 3e 30 [2] 22 37 [2] 3e 18 }

  condition:
    any of them
}