rule TTP_XOR_QUAD_CurrentVersionRun_44e2 {
  strings:
    $key_44e2 = { 17 8d [2] 33 83 [2] 18 af [2] 36 8d [2] 22 96 [2] 2d 8c [2] 33 91 [2] 31 90 [2] 2a 96 [2] 36 91 [2] 2a be }

  condition:
    any of them
}