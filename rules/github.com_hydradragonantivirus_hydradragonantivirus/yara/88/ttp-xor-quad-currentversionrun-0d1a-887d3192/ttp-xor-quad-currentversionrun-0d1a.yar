rule TTP_XOR_QUAD_CurrentVersionRun_0d1a {
  strings:
    $key_0d1a = { 5e 75 [2] 7a 7b [2] 51 57 [2] 7f 75 [2] 6b 6e [2] 64 74 [2] 7a 69 [2] 78 68 [2] 63 6e [2] 7f 69 [2] 63 46 }

  condition:
    any of them
}