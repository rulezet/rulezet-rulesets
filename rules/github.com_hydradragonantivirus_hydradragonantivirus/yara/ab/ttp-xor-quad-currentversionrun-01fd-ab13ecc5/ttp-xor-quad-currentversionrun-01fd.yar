rule TTP_XOR_QUAD_CurrentVersionRun_01fd {
  strings:
    $key_01fd = { 52 92 [2] 76 9c [2] 5d b0 [2] 73 92 [2] 67 89 [2] 68 93 [2] 76 8e [2] 74 8f [2] 6f 89 [2] 73 8e [2] 6f a1 }

  condition:
    any of them
}