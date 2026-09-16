rule TTP_XOR_QUAD_CurrentVersionRun_0f34 {
  strings:
    $key_0f34 = { 5c 5b [2] 78 55 [2] 53 79 [2] 7d 5b [2] 69 40 [2] 66 5a [2] 78 47 [2] 7a 46 [2] 61 40 [2] 7d 47 [2] 61 68 }

  condition:
    any of them
}