rule TTP_XOR_QUAD_CurrentVersionRun_7227 {
  strings:
    $key_7227 = { 21 48 [2] 05 46 [2] 2e 6a [2] 00 48 [2] 14 53 [2] 1b 49 [2] 05 54 [2] 07 55 [2] 1c 53 [2] 00 54 [2] 1c 7b }

  condition:
    any of them
}