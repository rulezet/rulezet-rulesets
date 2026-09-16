rule TTP_XOR_QUAD_CurrentVersionRun_0e05 {
  strings:
    $key_0e05 = { 5d 6a [2] 79 64 [2] 52 48 [2] 7c 6a [2] 68 71 [2] 67 6b [2] 79 76 [2] 7b 77 [2] 60 71 [2] 7c 76 [2] 60 59 }

  condition:
    any of them
}