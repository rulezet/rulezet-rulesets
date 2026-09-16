rule TTP_XOR_QUAD_CurrentVersionRun_7ae2 {
  strings:
    $key_7ae2 = { 29 8d [2] 0d 83 [2] 26 af [2] 08 8d [2] 1c 96 [2] 13 8c [2] 0d 91 [2] 0f 90 [2] 14 96 [2] 08 91 [2] 14 be }

  condition:
    any of them
}