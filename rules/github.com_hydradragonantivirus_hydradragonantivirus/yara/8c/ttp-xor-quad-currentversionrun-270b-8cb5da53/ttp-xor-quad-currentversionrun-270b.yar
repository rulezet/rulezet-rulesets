rule TTP_XOR_QUAD_CurrentVersionRun_270b {
  strings:
    $key_270b = { 74 64 [2] 50 6a [2] 7b 46 [2] 55 64 [2] 41 7f [2] 4e 65 [2] 50 78 [2] 52 79 [2] 49 7f [2] 55 78 [2] 49 57 }

  condition:
    any of them
}