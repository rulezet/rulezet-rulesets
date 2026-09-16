rule TTP_XOR_QUAD_CurrentVersionRun_507b {
  strings:
    $key_507b = { 03 14 [2] 27 1a [2] 0c 36 [2] 22 14 [2] 36 0f [2] 39 15 [2] 27 08 [2] 25 09 [2] 3e 0f [2] 22 08 [2] 3e 27 }

  condition:
    any of them
}