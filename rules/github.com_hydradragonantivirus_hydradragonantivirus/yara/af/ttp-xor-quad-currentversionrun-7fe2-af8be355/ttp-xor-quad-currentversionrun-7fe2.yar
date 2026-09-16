rule TTP_XOR_QUAD_CurrentVersionRun_7fe2 {
  strings:
    $key_7fe2 = { 2c 8d [2] 08 83 [2] 23 af [2] 0d 8d [2] 19 96 [2] 16 8c [2] 08 91 [2] 0a 90 [2] 11 96 [2] 0d 91 [2] 11 be }

  condition:
    any of them
}