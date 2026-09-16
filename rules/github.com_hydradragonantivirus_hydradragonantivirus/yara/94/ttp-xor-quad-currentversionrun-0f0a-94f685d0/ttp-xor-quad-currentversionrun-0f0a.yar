rule TTP_XOR_QUAD_CurrentVersionRun_0f0a {
  strings:
    $key_0f0a = { 5c 65 [2] 78 6b [2] 53 47 [2] 7d 65 [2] 69 7e [2] 66 64 [2] 78 79 [2] 7a 78 [2] 61 7e [2] 7d 79 [2] 61 56 }

  condition:
    any of them
}