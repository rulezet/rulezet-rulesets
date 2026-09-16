rule TTP_XOR_QUAD_CurrentVersionRun_3f44 {
  strings:
    $key_3f44 = { 6c 2b [2] 48 25 [2] 63 09 [2] 4d 2b [2] 59 30 [2] 56 2a [2] 48 37 [2] 4a 36 [2] 51 30 [2] 4d 37 [2] 51 18 }

  condition:
    any of them
}