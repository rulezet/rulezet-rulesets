rule TTP_XOR_QUAD_CurrentVersionRun_2505 {
  strings:
    $key_2505 = { 76 6a [2] 52 64 [2] 79 48 [2] 57 6a [2] 43 71 [2] 4c 6b [2] 52 76 [2] 50 77 [2] 4b 71 [2] 57 76 [2] 4b 59 }

  condition:
    any of them
}