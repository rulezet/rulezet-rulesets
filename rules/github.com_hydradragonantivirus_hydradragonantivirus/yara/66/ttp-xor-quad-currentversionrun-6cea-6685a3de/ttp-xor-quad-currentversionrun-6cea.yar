rule TTP_XOR_QUAD_CurrentVersionRun_6cea {
  strings:
    $key_6cea = { 3f 85 [2] 1b 8b [2] 30 a7 [2] 1e 85 [2] 0a 9e [2] 05 84 [2] 1b 99 [2] 19 98 [2] 02 9e [2] 1e 99 [2] 02 b6 }

  condition:
    any of them
}