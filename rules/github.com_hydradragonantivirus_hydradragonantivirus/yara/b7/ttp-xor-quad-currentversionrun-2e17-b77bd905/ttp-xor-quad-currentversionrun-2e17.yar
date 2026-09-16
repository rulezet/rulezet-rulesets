rule TTP_XOR_QUAD_CurrentVersionRun_2e17 {
  strings:
    $key_2e17 = { 7d 78 [2] 59 76 [2] 72 5a [2] 5c 78 [2] 48 63 [2] 47 79 [2] 59 64 [2] 5b 65 [2] 40 63 [2] 5c 64 [2] 40 4b }

  condition:
    any of them
}