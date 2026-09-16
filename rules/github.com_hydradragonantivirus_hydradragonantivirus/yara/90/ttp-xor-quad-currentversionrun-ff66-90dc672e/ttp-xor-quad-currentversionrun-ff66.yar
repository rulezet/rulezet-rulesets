rule TTP_XOR_QUAD_CurrentVersionRun_ff66 {
  strings:
    $key_ff66 = { ac 09 [2] 88 07 [2] a3 2b [2] 8d 09 [2] 99 12 [2] 96 08 [2] 88 15 [2] 8a 14 [2] 91 12 [2] 8d 15 [2] 91 3a }

  condition:
    any of them
}