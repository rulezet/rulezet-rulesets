rule TTP_XOR_QUAD_CurrentVersionRun_2ae2 {
  strings:
    $key_2ae2 = { 79 8d [2] 5d 83 [2] 76 af [2] 58 8d [2] 4c 96 [2] 43 8c [2] 5d 91 [2] 5f 90 [2] 44 96 [2] 58 91 [2] 44 be }

  condition:
    any of them
}