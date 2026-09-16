rule TTP_XOR_QUAD_CurrentVersionRun_7de2 {
  strings:
    $key_7de2 = { 2e 8d [2] 0a 83 [2] 21 af [2] 0f 8d [2] 1b 96 [2] 14 8c [2] 0a 91 [2] 08 90 [2] 13 96 [2] 0f 91 [2] 13 be }

  condition:
    any of them
}