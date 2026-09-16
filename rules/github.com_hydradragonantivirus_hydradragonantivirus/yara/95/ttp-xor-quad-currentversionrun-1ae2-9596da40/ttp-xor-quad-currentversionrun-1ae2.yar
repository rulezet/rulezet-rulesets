rule TTP_XOR_QUAD_CurrentVersionRun_1ae2 {
  strings:
    $key_1ae2 = { 49 8d [2] 6d 83 [2] 46 af [2] 68 8d [2] 7c 96 [2] 73 8c [2] 6d 91 [2] 6f 90 [2] 74 96 [2] 68 91 [2] 74 be }

  condition:
    any of them
}