rule TTP_XOR_QUAD_CurrentVersionRun_6f21 {
  strings:
    $key_6f21 = { 3c 4e [2] 18 40 [2] 33 6c [2] 1d 4e [2] 09 55 [2] 06 4f [2] 18 52 [2] 1a 53 [2] 01 55 [2] 1d 52 [2] 01 7d }

  condition:
    any of them
}