rule TTP_XOR_QUAD_CurrentVersionRun_131a {
  strings:
    $key_131a = { 40 75 [2] 64 7b [2] 4f 57 [2] 61 75 [2] 75 6e [2] 7a 74 [2] 64 69 [2] 66 68 [2] 7d 6e [2] 61 69 [2] 7d 46 }

  condition:
    any of them
}