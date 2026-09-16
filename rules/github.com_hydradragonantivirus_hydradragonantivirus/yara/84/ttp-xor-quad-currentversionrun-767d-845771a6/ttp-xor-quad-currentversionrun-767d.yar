rule TTP_XOR_QUAD_CurrentVersionRun_767d {
  strings:
    $key_767d = { 25 12 [2] 01 1c [2] 2a 30 [2] 04 12 [2] 10 09 [2] 1f 13 [2] 01 0e [2] 03 0f [2] 18 09 [2] 04 0e [2] 18 21 }

  condition:
    any of them
}