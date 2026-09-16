rule TTP_XOR_QUAD_CurrentVersionRun_1468 {
  strings:
    $key_1468 = { 47 07 [2] 63 09 [2] 48 25 [2] 66 07 [2] 72 1c [2] 7d 06 [2] 63 1b [2] 61 1a [2] 7a 1c [2] 66 1b [2] 7a 34 }

  condition:
    any of them
}