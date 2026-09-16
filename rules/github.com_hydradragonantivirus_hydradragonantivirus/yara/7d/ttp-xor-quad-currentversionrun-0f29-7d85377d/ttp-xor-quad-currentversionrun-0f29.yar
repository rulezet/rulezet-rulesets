rule TTP_XOR_QUAD_CurrentVersionRun_0f29 {
  strings:
    $key_0f29 = { 5c 46 [2] 78 48 [2] 53 64 [2] 7d 46 [2] 69 5d [2] 66 47 [2] 78 5a [2] 7a 5b [2] 61 5d [2] 7d 5a [2] 61 75 }

  condition:
    any of them
}