rule TTP_XOR_QUAD_CurrentVersionRun_153b {
  strings:
    $key_153b = { 46 54 [2] 62 5a [2] 49 76 [2] 67 54 [2] 73 4f [2] 7c 55 [2] 62 48 [2] 60 49 [2] 7b 4f [2] 67 48 [2] 7b 67 }

  condition:
    any of them
}