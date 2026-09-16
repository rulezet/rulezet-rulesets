rule TTP_XOR_QUAD_CurrentVersionRun_7d71 {
  strings:
    $key_7d71 = { 2e 1e [2] 0a 10 [2] 21 3c [2] 0f 1e [2] 1b 05 [2] 14 1f [2] 0a 02 [2] 08 03 [2] 13 05 [2] 0f 02 [2] 13 2d }

  condition:
    any of them
}