rule TTP_XOR_QUAD_CurrentVersionRun_7331 {
  strings:
    $key_7331 = { 20 5e [2] 04 50 [2] 2f 7c [2] 01 5e [2] 15 45 [2] 1a 5f [2] 04 42 [2] 06 43 [2] 1d 45 [2] 01 42 [2] 1d 6d }

  condition:
    any of them
}