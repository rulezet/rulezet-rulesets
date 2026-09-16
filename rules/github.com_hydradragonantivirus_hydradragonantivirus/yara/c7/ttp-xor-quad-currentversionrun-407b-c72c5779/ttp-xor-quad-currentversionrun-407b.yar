rule TTP_XOR_QUAD_CurrentVersionRun_407b {
  strings:
    $key_407b = { 13 14 [2] 37 1a [2] 1c 36 [2] 32 14 [2] 26 0f [2] 29 15 [2] 37 08 [2] 35 09 [2] 2e 0f [2] 32 08 [2] 2e 27 }

  condition:
    any of them
}