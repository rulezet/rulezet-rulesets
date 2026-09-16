rule TTP_XOR_QUAD_CurrentVersionRun_0a27 {
  strings:
    $key_0a27 = { 59 48 [2] 7d 46 [2] 56 6a [2] 78 48 [2] 6c 53 [2] 63 49 [2] 7d 54 [2] 7f 55 [2] 64 53 [2] 78 54 [2] 64 7b }

  condition:
    any of them
}