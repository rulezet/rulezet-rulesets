rule TTP_XOR_QUAD_CurrentVersionRun_e266 {
  strings:
    $key_e266 = { b1 09 [2] 95 07 [2] be 2b [2] 90 09 [2] 84 12 [2] 8b 08 [2] 95 15 [2] 97 14 [2] 8c 12 [2] 90 15 [2] 8c 3a }

  condition:
    any of them
}