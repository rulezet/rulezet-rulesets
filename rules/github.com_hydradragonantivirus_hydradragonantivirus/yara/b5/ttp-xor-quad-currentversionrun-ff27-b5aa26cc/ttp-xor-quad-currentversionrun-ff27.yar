rule TTP_XOR_QUAD_CurrentVersionRun_ff27 {
  strings:
    $key_ff27 = { ac 48 [2] 88 46 [2] a3 6a [2] 8d 48 [2] 99 53 [2] 96 49 [2] 88 54 [2] 8a 55 [2] 91 53 [2] 8d 54 [2] 91 7b }

  condition:
    any of them
}