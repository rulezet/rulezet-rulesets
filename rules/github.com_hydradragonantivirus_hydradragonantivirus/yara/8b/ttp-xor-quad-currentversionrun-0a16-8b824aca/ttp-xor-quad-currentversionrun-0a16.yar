rule TTP_XOR_QUAD_CurrentVersionRun_0a16 {
  strings:
    $key_0a16 = { 59 79 [2] 7d 77 [2] 56 5b [2] 78 79 [2] 6c 62 [2] 63 78 [2] 7d 65 [2] 7f 64 [2] 64 62 [2] 78 65 [2] 64 4a }

  condition:
    any of them
}