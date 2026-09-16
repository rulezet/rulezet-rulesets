rule TTP_XOR_QUAD_CurrentVersionRun_0905 {
  strings:
    $key_0905 = { 5a 6a [2] 7e 64 [2] 55 48 [2] 7b 6a [2] 6f 71 [2] 60 6b [2] 7e 76 [2] 7c 77 [2] 67 71 [2] 7b 76 [2] 67 59 }

  condition:
    any of them
}