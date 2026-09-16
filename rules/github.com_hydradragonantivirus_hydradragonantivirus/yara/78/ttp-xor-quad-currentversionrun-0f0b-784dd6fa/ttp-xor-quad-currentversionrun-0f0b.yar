rule TTP_XOR_QUAD_CurrentVersionRun_0f0b {
  strings:
    $key_0f0b = { 5c 64 [2] 78 6a [2] 53 46 [2] 7d 64 [2] 69 7f [2] 66 65 [2] 78 78 [2] 7a 79 [2] 61 7f [2] 7d 78 [2] 61 57 }

  condition:
    any of them
}