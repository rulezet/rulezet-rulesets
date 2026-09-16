rule TTP_XOR_QUAD_CurrentVersionRun_0a68 {
  strings:
    $key_0a68 = { 59 07 [2] 7d 09 [2] 56 25 [2] 78 07 [2] 6c 1c [2] 63 06 [2] 7d 1b [2] 7f 1a [2] 64 1c [2] 78 1b [2] 64 34 }

  condition:
    any of them
}