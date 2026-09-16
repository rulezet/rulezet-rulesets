rule TTP_XOR_QUAD_CurrentVersionRun_1866 {
  strings:
    $key_1866 = { 4b 09 [2] 6f 07 [2] 44 2b [2] 6a 09 [2] 7e 12 [2] 71 08 [2] 6f 15 [2] 6d 14 [2] 76 12 [2] 6a 15 [2] 76 3a }

  condition:
    any of them
}