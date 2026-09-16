rule TTP_XOR_QUAD_CurrentVersionRun_1505 {
  strings:
    $key_1505 = { 46 6a [2] 62 64 [2] 49 48 [2] 67 6a [2] 73 71 [2] 7c 6b [2] 62 76 [2] 60 77 [2] 7b 71 [2] 67 76 [2] 7b 59 }

  condition:
    any of them
}