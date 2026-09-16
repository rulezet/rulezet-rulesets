rule TTP_XOR_QUAD_CurrentVersionRun_f366 {
  strings:
    $key_f366 = { a0 09 [2] 84 07 [2] af 2b [2] 81 09 [2] 95 12 [2] 9a 08 [2] 84 15 [2] 86 14 [2] 9d 12 [2] 81 15 [2] 9d 3a }

  condition:
    any of them
}