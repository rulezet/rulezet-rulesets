rule TTP_XOR_QUAD_CurrentVersionRun_4866 {
  strings:
    $key_4866 = { 1b 09 [2] 3f 07 [2] 14 2b [2] 3a 09 [2] 2e 12 [2] 21 08 [2] 3f 15 [2] 3d 14 [2] 26 12 [2] 3a 15 [2] 26 3a }

  condition:
    any of them
}