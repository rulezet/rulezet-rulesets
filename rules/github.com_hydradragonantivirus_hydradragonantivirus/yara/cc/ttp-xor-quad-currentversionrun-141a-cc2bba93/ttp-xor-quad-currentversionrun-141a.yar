rule TTP_XOR_QUAD_CurrentVersionRun_141a {
  strings:
    $key_141a = { 47 75 [2] 63 7b [2] 48 57 [2] 66 75 [2] 72 6e [2] 7d 74 [2] 63 69 [2] 61 68 [2] 7a 6e [2] 66 69 [2] 7a 46 }

  condition:
    any of them
}