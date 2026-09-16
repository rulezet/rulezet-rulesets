rule TTP_XOR_QUAD_CurrentVersionRun_061a {
  strings:
    $key_061a = { 55 75 [2] 71 7b [2] 5a 57 [2] 74 75 [2] 60 6e [2] 6f 74 [2] 71 69 [2] 73 68 [2] 68 6e [2] 74 69 [2] 68 46 }

  condition:
    any of them
}