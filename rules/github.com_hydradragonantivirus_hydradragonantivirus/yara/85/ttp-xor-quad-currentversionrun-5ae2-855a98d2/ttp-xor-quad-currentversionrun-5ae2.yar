rule TTP_XOR_QUAD_CurrentVersionRun_5ae2 {
  strings:
    $key_5ae2 = { 09 8d [2] 2d 83 [2] 06 af [2] 28 8d [2] 3c 96 [2] 33 8c [2] 2d 91 [2] 2f 90 [2] 34 96 [2] 28 91 [2] 34 be }

  condition:
    any of them
}