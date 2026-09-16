rule TTP_XOR_QUAD_CurrentVersionRun_66e2 {
  strings:
    $key_66e2 = { 35 8d [2] 11 83 [2] 3a af [2] 14 8d [2] 00 96 [2] 0f 8c [2] 11 91 [2] 13 90 [2] 08 96 [2] 14 91 [2] 08 be }

  condition:
    any of them
}