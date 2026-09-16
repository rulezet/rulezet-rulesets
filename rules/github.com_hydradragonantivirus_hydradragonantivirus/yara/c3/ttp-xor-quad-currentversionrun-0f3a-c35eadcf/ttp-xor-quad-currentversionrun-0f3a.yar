rule TTP_XOR_QUAD_CurrentVersionRun_0f3a {
  strings:
    $key_0f3a = { 5c 55 [2] 78 5b [2] 53 77 [2] 7d 55 [2] 69 4e [2] 66 54 [2] 78 49 [2] 7a 48 [2] 61 4e [2] 7d 49 [2] 61 66 }

  condition:
    any of them
}