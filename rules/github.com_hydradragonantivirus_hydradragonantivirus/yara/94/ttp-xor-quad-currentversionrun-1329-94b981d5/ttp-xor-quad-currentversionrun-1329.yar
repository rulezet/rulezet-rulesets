rule TTP_XOR_QUAD_CurrentVersionRun_1329 {
  strings:
    $key_1329 = { 40 46 [2] 64 48 [2] 4f 64 [2] 61 46 [2] 75 5d [2] 7a 47 [2] 64 5a [2] 66 5b [2] 7d 5d [2] 61 5a [2] 7d 75 }

  condition:
    any of them
}