rule TTP_XOR_QUAD_CurrentVersionRun_100b {
  strings:
    $key_100b = { 43 64 [2] 67 6a [2] 4c 46 [2] 62 64 [2] 76 7f [2] 79 65 [2] 67 78 [2] 65 79 [2] 7e 7f [2] 62 78 [2] 7e 57 }

  condition:
    any of them
}