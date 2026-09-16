rule TTP_XOR_QUAD_CurrentVersionRun_0a65 {
  strings:
    $key_0a65 = { 59 0a [2] 7d 04 [2] 56 28 [2] 78 0a [2] 6c 11 [2] 63 0b [2] 7d 16 [2] 7f 17 [2] 64 11 [2] 78 16 [2] 64 39 }

  condition:
    any of them
}