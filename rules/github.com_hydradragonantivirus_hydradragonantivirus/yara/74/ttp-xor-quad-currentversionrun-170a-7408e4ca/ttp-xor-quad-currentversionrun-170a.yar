rule TTP_XOR_QUAD_CurrentVersionRun_170a {
  strings:
    $key_170a = { 44 65 [2] 60 6b [2] 4b 47 [2] 65 65 [2] 71 7e [2] 7e 64 [2] 60 79 [2] 62 78 [2] 79 7e [2] 65 79 [2] 79 56 }

  condition:
    any of them
}