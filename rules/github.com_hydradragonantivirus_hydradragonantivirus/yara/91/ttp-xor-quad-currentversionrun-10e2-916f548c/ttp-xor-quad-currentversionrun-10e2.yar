rule TTP_XOR_QUAD_CurrentVersionRun_10e2 {
  strings:
    $key_10e2 = { 43 8d [2] 67 83 [2] 4c af [2] 62 8d [2] 76 96 [2] 79 8c [2] 67 91 [2] 65 90 [2] 7e 96 [2] 62 91 [2] 7e be }

  condition:
    any of them
}