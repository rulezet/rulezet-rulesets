rule TTP_XOR_QUAD_CurrentVersionRun_0a19 {
  strings:
    $key_0a19 = { 59 76 [2] 7d 78 [2] 56 54 [2] 78 76 [2] 6c 6d [2] 63 77 [2] 7d 6a [2] 7f 6b [2] 64 6d [2] 78 6a [2] 64 45 }

  condition:
    any of them
}