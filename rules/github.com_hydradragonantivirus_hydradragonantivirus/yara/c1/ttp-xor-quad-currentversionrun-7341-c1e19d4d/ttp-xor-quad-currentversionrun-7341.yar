rule TTP_XOR_QUAD_CurrentVersionRun_7341 {
  strings:
    $key_7341 = { 20 2e [2] 04 20 [2] 2f 0c [2] 01 2e [2] 15 35 [2] 1a 2f [2] 04 32 [2] 06 33 [2] 1d 35 [2] 01 32 [2] 1d 1d }

  condition:
    any of them
}