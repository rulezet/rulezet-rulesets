rule TTP_XOR_QUAD_CurrentVersionRun_781d {
  strings:
    $key_781d = { 2b 72 [2] 0f 7c [2] 24 50 [2] 0a 72 [2] 1e 69 [2] 11 73 [2] 0f 6e [2] 0d 6f [2] 16 69 [2] 0a 6e [2] 16 41 }

  condition:
    any of them
}