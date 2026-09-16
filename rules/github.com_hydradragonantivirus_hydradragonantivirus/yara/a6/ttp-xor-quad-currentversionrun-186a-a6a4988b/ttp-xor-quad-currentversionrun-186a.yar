rule TTP_XOR_QUAD_CurrentVersionRun_186a {
  strings:
    $key_186a = { 4b 05 [2] 6f 0b [2] 44 27 [2] 6a 05 [2] 7e 1e [2] 71 04 [2] 6f 19 [2] 6d 18 [2] 76 1e [2] 6a 19 [2] 76 36 }

  condition:
    any of them
}