rule TTP_XOR_QUAD_CurrentVersionRun_0f35 {
  strings:
    $key_0f35 = { 5c 5a [2] 78 54 [2] 53 78 [2] 7d 5a [2] 69 41 [2] 66 5b [2] 78 46 [2] 7a 47 [2] 61 41 [2] 7d 46 [2] 61 69 }

  condition:
    any of them
}