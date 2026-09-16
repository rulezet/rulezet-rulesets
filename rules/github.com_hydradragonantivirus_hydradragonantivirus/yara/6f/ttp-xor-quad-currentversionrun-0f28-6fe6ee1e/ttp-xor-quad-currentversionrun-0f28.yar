rule TTP_XOR_QUAD_CurrentVersionRun_0f28 {
  strings:
    $key_0f28 = { 5c 47 [2] 78 49 [2] 53 65 [2] 7d 47 [2] 69 5c [2] 66 46 [2] 78 5b [2] 7a 5a [2] 61 5c [2] 7d 5b [2] 61 74 }

  condition:
    any of them
}