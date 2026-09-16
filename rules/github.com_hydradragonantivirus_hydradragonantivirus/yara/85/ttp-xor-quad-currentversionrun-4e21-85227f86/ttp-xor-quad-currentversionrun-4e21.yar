rule TTP_XOR_QUAD_CurrentVersionRun_4e21 {
  strings:
    $key_4e21 = { 1d 4e [2] 39 40 [2] 12 6c [2] 3c 4e [2] 28 55 [2] 27 4f [2] 39 52 [2] 3b 53 [2] 20 55 [2] 3c 52 [2] 20 7d }

  condition:
    any of them
}