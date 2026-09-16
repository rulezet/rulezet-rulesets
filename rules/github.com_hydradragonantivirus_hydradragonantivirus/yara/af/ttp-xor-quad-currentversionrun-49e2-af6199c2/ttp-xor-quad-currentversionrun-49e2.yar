rule TTP_XOR_QUAD_CurrentVersionRun_49e2 {
  strings:
    $key_49e2 = { 1a 8d [2] 3e 83 [2] 15 af [2] 3b 8d [2] 2f 96 [2] 20 8c [2] 3e 91 [2] 3c 90 [2] 27 96 [2] 3b 91 [2] 27 be }

  condition:
    any of them
}