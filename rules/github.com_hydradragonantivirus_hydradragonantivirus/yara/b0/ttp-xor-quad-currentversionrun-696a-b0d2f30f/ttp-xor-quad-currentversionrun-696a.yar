rule TTP_XOR_QUAD_CurrentVersionRun_696a {
  strings:
    $key_696a = { 3a 05 [2] 1e 0b [2] 35 27 [2] 1b 05 [2] 0f 1e [2] 00 04 [2] 1e 19 [2] 1c 18 [2] 07 1e [2] 1b 19 [2] 07 36 }

  condition:
    any of them
}