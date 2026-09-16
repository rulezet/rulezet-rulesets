rule TTP_XOR_QUAD_CurrentVersionRun_723b {
  strings:
    $key_723b = { 21 54 [2] 05 5a [2] 2e 76 [2] 00 54 [2] 14 4f [2] 1b 55 [2] 05 48 [2] 07 49 [2] 1c 4f [2] 00 48 [2] 1c 67 }

  condition:
    any of them
}