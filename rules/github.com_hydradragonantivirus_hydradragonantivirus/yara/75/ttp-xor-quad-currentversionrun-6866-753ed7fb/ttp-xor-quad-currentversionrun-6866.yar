rule TTP_XOR_QUAD_CurrentVersionRun_6866 {
  strings:
    $key_6866 = { 3b 09 [2] 1f 07 [2] 34 2b [2] 1a 09 [2] 0e 12 [2] 01 08 [2] 1f 15 [2] 1d 14 [2] 06 12 [2] 1a 15 [2] 06 3a }

  condition:
    any of them
}