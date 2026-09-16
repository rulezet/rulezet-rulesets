rule TTP_XOR_QUAD_CurrentVersionRun_0a78 {
  strings:
    $key_0a78 = { 59 17 [2] 7d 19 [2] 56 35 [2] 78 17 [2] 6c 0c [2] 63 16 [2] 7d 0b [2] 7f 0a [2] 64 0c [2] 78 0b [2] 64 24 }

  condition:
    any of them
}