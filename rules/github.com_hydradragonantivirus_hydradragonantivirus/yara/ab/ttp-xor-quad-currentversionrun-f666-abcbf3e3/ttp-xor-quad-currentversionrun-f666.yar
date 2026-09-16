rule TTP_XOR_QUAD_CurrentVersionRun_f666 {
  strings:
    $key_f666 = { a5 09 [2] 81 07 [2] aa 2b [2] 84 09 [2] 90 12 [2] 9f 08 [2] 81 15 [2] 83 14 [2] 98 12 [2] 84 15 [2] 98 3a }

  condition:
    any of them
}