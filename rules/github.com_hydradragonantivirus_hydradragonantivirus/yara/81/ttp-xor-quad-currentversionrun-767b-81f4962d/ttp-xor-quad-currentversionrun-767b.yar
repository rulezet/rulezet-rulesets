rule TTP_XOR_QUAD_CurrentVersionRun_767b {
  strings:
    $key_767b = { 25 14 [2] 01 1a [2] 2a 36 [2] 04 14 [2] 10 0f [2] 1f 15 [2] 01 08 [2] 03 09 [2] 18 0f [2] 04 08 [2] 18 27 }

  condition:
    any of them
}