rule TTP_XOR_QUAD_CurrentVersionRun_1be2 {
  strings:
    $key_1be2 = { 48 8d [2] 6c 83 [2] 47 af [2] 69 8d [2] 7d 96 [2] 72 8c [2] 6c 91 [2] 6e 90 [2] 75 96 [2] 69 91 [2] 75 be }

  condition:
    any of them
}