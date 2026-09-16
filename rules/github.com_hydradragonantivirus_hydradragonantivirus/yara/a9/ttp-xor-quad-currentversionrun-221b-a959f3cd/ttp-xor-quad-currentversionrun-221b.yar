rule TTP_XOR_QUAD_CurrentVersionRun_221b {
  strings:
    $key_221b = { 71 74 [2] 55 7a [2] 7e 56 [2] 50 74 [2] 44 6f [2] 4b 75 [2] 55 68 [2] 57 69 [2] 4c 6f [2] 50 68 [2] 4c 47 }

  condition:
    any of them
}