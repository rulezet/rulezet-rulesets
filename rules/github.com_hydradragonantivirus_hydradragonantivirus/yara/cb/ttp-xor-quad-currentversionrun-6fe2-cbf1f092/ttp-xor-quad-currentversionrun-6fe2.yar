rule TTP_XOR_QUAD_CurrentVersionRun_6fe2 {
  strings:
    $key_6fe2 = { 3c 8d [2] 18 83 [2] 33 af [2] 1d 8d [2] 09 96 [2] 06 8c [2] 18 91 [2] 1a 90 [2] 01 96 [2] 1d 91 [2] 01 be }

  condition:
    any of them
}