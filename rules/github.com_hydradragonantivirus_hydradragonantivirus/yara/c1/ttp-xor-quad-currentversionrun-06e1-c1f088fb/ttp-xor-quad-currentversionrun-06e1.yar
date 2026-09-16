rule TTP_XOR_QUAD_CurrentVersionRun_06e1 {
  strings:
    $key_06e1 = { 55 8e [2] 71 80 [2] 5a ac [2] 74 8e [2] 60 95 [2] 6f 8f [2] 71 92 [2] 73 93 [2] 68 95 [2] 74 92 [2] 68 bd }

  condition:
    any of them
}