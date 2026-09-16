rule TTP_XOR_QUAD_CurrentVersionRun_72e2 {
  strings:
    $key_72e2 = { 21 8d [2] 05 83 [2] 2e af [2] 00 8d [2] 14 96 [2] 1b 8c [2] 05 91 [2] 07 90 [2] 1c 96 [2] 00 91 [2] 1c be }

  condition:
    any of them
}