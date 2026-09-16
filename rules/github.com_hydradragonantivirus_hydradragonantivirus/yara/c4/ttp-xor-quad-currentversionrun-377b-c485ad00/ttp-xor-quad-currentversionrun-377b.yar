rule TTP_XOR_QUAD_CurrentVersionRun_377b {
  strings:
    $key_377b = { 64 14 [2] 40 1a [2] 6b 36 [2] 45 14 [2] 51 0f [2] 5e 15 [2] 40 08 [2] 42 09 [2] 59 0f [2] 45 08 [2] 59 27 }

  condition:
    any of them
}