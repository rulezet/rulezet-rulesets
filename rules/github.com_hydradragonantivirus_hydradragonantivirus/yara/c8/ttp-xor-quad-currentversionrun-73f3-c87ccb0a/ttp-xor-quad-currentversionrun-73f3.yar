rule TTP_XOR_QUAD_CurrentVersionRun_73f3 {
  strings:
    $key_73f3 = { 20 9c [2] 04 92 [2] 2f be [2] 01 9c [2] 15 87 [2] 1a 9d [2] 04 80 [2] 06 81 [2] 1d 87 [2] 01 80 [2] 1d af }

  condition:
    any of them
}