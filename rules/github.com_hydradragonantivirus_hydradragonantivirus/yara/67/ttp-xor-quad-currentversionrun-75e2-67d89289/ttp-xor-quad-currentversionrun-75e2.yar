rule TTP_XOR_QUAD_CurrentVersionRun_75e2 {
  strings:
    $key_75e2 = { 26 8d [2] 02 83 [2] 29 af [2] 07 8d [2] 13 96 [2] 1c 8c [2] 02 91 [2] 00 90 [2] 1b 96 [2] 07 91 [2] 1b be }

  condition:
    any of them
}