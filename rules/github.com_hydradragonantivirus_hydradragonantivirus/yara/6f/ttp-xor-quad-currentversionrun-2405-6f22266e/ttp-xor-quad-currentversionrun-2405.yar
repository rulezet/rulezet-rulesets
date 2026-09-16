rule TTP_XOR_QUAD_CurrentVersionRun_2405 {
  strings:
    $key_2405 = { 77 6a [2] 53 64 [2] 78 48 [2] 56 6a [2] 42 71 [2] 4d 6b [2] 53 76 [2] 51 77 [2] 4a 71 [2] 56 76 [2] 4a 59 }

  condition:
    any of them
}