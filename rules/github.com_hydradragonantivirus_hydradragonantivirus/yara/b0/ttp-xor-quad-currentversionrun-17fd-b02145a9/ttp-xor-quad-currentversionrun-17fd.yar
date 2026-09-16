rule TTP_XOR_QUAD_CurrentVersionRun_17fd {
  strings:
    $key_17fd = { 44 92 [2] 60 9c [2] 4b b0 [2] 65 92 [2] 71 89 [2] 7e 93 [2] 60 8e [2] 62 8f [2] 79 89 [2] 65 8e [2] 79 a1 }

  condition:
    any of them
}