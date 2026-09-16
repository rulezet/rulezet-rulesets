rule TTP_XOR_QUAD_CurrentVersionRun_64e2 {
  strings:
    $key_64e2 = { 37 8d [2] 13 83 [2] 38 af [2] 16 8d [2] 02 96 [2] 0d 8c [2] 13 91 [2] 11 90 [2] 0a 96 [2] 16 91 [2] 0a be }

  condition:
    any of them
}