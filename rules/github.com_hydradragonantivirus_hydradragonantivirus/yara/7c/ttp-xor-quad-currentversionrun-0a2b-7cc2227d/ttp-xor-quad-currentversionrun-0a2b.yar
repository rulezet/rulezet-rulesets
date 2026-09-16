rule TTP_XOR_QUAD_CurrentVersionRun_0a2b {
  strings:
    $key_0a2b = { 59 44 [2] 7d 4a [2] 56 66 [2] 78 44 [2] 6c 5f [2] 63 45 [2] 7d 58 [2] 7f 59 [2] 64 5f [2] 78 58 [2] 64 77 }

  condition:
    any of them
}