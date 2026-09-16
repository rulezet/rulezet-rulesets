rule TTP_XOR_QUAD_CurrentVersionRun_7211 {
  strings:
    $key_7211 = { 21 7e [2] 05 70 [2] 2e 5c [2] 00 7e [2] 14 65 [2] 1b 7f [2] 05 62 [2] 07 63 [2] 1c 65 [2] 00 62 [2] 1c 4d }

  condition:
    any of them
}