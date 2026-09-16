rule TTP_XOR_QUAD_CurrentVersionRun_2e3b {
  strings:
    $key_2e3b = { 7d 54 [2] 59 5a [2] 72 76 [2] 5c 54 [2] 48 4f [2] 47 55 [2] 59 48 [2] 5b 49 [2] 40 4f [2] 5c 48 [2] 40 67 }

  condition:
    any of them
}