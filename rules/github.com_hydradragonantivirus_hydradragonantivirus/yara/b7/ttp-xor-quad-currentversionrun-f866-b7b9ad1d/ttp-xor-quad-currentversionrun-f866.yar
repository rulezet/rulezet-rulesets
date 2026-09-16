rule TTP_XOR_QUAD_CurrentVersionRun_f866 {
  strings:
    $key_f866 = { ab 09 [2] 8f 07 [2] a4 2b [2] 8a 09 [2] 9e 12 [2] 91 08 [2] 8f 15 [2] 8d 14 [2] 96 12 [2] 8a 15 [2] 96 3a }

  condition:
    any of them
}