rule TTP_XOR_QUAD_CurrentVersionRun_69e2 {
  strings:
    $key_69e2 = { 3a 8d [2] 1e 83 [2] 35 af [2] 1b 8d [2] 0f 96 [2] 00 8c [2] 1e 91 [2] 1c 90 [2] 07 96 [2] 1b 91 [2] 07 be }

  condition:
    any of them
}