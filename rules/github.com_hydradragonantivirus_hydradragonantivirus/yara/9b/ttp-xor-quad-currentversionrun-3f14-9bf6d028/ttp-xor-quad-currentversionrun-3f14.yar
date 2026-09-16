rule TTP_XOR_QUAD_CurrentVersionRun_3f14 {
  strings:
    $key_3f14 = { 6c 7b [2] 48 75 [2] 63 59 [2] 4d 7b [2] 59 60 [2] 56 7a [2] 48 67 [2] 4a 66 [2] 51 60 [2] 4d 67 [2] 51 48 }

  condition:
    any of them
}