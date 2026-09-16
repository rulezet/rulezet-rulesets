rule TTP_XOR_QUAD_CurrentVersionRun_7be2 {
  strings:
    $key_7be2 = { 28 8d [2] 0c 83 [2] 27 af [2] 09 8d [2] 1d 96 [2] 12 8c [2] 0c 91 [2] 0e 90 [2] 15 96 [2] 09 91 [2] 15 be }

  condition:
    any of them
}