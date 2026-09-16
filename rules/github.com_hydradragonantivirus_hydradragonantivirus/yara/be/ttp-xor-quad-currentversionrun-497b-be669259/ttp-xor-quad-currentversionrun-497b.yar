rule TTP_XOR_QUAD_CurrentVersionRun_497b {
  strings:
    $key_497b = { 1a 14 [2] 3e 1a [2] 15 36 [2] 3b 14 [2] 2f 0f [2] 20 15 [2] 3e 08 [2] 3c 09 [2] 27 0f [2] 3b 08 [2] 27 27 }

  condition:
    any of them
}