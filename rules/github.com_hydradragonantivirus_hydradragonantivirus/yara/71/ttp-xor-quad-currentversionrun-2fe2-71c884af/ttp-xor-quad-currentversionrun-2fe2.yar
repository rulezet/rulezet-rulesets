rule TTP_XOR_QUAD_CurrentVersionRun_2fe2 {
  strings:
    $key_2fe2 = { 7c 8d [2] 58 83 [2] 73 af [2] 5d 8d [2] 49 96 [2] 46 8c [2] 58 91 [2] 5a 90 [2] 41 96 [2] 5d 91 [2] 41 be }

  condition:
    any of them
}