rule TTP_XOR_QUAD_CurrentVersionRun_78e2 {
  strings:
    $key_78e2 = { 2b 8d [2] 0f 83 [2] 24 af [2] 0a 8d [2] 1e 96 [2] 11 8c [2] 0f 91 [2] 0d 90 [2] 16 96 [2] 0a 91 [2] 16 be }

  condition:
    any of them
}