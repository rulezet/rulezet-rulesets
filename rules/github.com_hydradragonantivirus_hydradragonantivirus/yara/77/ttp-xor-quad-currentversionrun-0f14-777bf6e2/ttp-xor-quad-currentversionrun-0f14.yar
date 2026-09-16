rule TTP_XOR_QUAD_CurrentVersionRun_0f14 {
  strings:
    $key_0f14 = { 5c 7b [2] 78 75 [2] 53 59 [2] 7d 7b [2] 69 60 [2] 66 7a [2] 78 67 [2] 7a 66 [2] 61 60 [2] 7d 67 [2] 61 48 }

  condition:
    any of them
}