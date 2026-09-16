rule TTP_XOR_QUAD_CurrentVersionRun_1c4a {
  strings:
    $key_1c4a = { 4f 25 [2] 6b 2b [2] 40 07 [2] 6e 25 [2] 7a 3e [2] 75 24 [2] 6b 39 [2] 69 38 [2] 72 3e [2] 6e 39 [2] 72 16 }

  condition:
    any of them
}