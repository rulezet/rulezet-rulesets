rule TTP_XOR_QUAD_CurrentVersionRun_371a {
  strings:
    $key_371a = { 64 75 [2] 40 7b [2] 6b 57 [2] 45 75 [2] 51 6e [2] 5e 74 [2] 40 69 [2] 42 68 [2] 59 6e [2] 45 69 [2] 59 46 }

  condition:
    any of them
}