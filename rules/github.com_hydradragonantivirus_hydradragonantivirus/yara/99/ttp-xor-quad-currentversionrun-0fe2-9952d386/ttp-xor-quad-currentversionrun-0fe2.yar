rule TTP_XOR_QUAD_CurrentVersionRun_0fe2 {
  strings:
    $key_0fe2 = { 5c 8d [2] 78 83 [2] 53 af [2] 7d 8d [2] 69 96 [2] 66 8c [2] 78 91 [2] 7a 90 [2] 61 96 [2] 7d 91 [2] 61 be }

  condition:
    any of them
}