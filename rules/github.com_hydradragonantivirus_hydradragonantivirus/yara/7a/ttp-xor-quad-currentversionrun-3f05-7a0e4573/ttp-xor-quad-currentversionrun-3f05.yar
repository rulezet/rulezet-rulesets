rule TTP_XOR_QUAD_CurrentVersionRun_3f05 {
  strings:
    $key_3f05 = { 6c 6a [2] 48 64 [2] 63 48 [2] 4d 6a [2] 59 71 [2] 56 6b [2] 48 76 [2] 4a 77 [2] 51 71 [2] 4d 76 [2] 51 59 }

  condition:
    any of them
}