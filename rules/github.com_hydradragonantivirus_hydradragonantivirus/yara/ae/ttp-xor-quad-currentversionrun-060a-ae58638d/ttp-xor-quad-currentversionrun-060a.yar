rule TTP_XOR_QUAD_CurrentVersionRun_060a {
  strings:
    $key_060a = { 55 65 [2] 71 6b [2] 5a 47 [2] 74 65 [2] 60 7e [2] 6f 64 [2] 71 79 [2] 73 78 [2] 68 7e [2] 74 79 [2] 68 56 }

  condition:
    any of them
}