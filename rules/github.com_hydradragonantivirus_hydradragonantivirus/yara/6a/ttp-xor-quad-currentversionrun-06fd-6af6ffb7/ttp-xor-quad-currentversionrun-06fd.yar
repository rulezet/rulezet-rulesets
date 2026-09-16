rule TTP_XOR_QUAD_CurrentVersionRun_06fd {
  strings:
    $key_06fd = { 55 92 [2] 71 9c [2] 5a b0 [2] 74 92 [2] 60 89 [2] 6f 93 [2] 71 8e [2] 73 8f [2] 68 89 [2] 74 8e [2] 68 a1 }

  condition:
    any of them
}