rule TTP_XOR_QUAD_CurrentVersionRun_696b {
  strings:
    $key_696b = { 3a 04 [2] 1e 0a [2] 35 26 [2] 1b 04 [2] 0f 1f [2] 00 05 [2] 1e 18 [2] 1c 19 [2] 07 1f [2] 1b 18 [2] 07 37 }

  condition:
    any of them
}