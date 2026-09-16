rule TTP_XOR_QUAD_CurrentVersionRun_0a18 {
  strings:
    $key_0a18 = { 59 77 [2] 7d 79 [2] 56 55 [2] 78 77 [2] 6c 6c [2] 63 76 [2] 7d 6b [2] 7f 6a [2] 64 6c [2] 78 6b [2] 64 44 }

  condition:
    any of them
}