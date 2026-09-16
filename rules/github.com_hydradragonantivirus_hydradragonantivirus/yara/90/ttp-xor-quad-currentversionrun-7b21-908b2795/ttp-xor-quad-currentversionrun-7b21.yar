rule TTP_XOR_QUAD_CurrentVersionRun_7b21 {
  strings:
    $key_7b21 = { 28 4e [2] 0c 40 [2] 27 6c [2] 09 4e [2] 1d 55 [2] 12 4f [2] 0c 52 [2] 0e 53 [2] 15 55 [2] 09 52 [2] 15 7d }

  condition:
    any of them
}