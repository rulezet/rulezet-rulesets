rule TTP_XOR_QUAD_CurrentVersionRun_167b {
  strings:
    $key_167b = { 45 14 [2] 61 1a [2] 4a 36 [2] 64 14 [2] 70 0f [2] 7f 15 [2] 61 08 [2] 63 09 [2] 78 0f [2] 64 08 [2] 78 27 }

  condition:
    any of them
}