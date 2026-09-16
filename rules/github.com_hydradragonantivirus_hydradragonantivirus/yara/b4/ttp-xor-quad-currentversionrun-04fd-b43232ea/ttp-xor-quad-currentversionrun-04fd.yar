rule TTP_XOR_QUAD_CurrentVersionRun_04fd {
  strings:
    $key_04fd = { 57 92 [2] 73 9c [2] 58 b0 [2] 76 92 [2] 62 89 [2] 6d 93 [2] 73 8e [2] 71 8f [2] 6a 89 [2] 76 8e [2] 6a a1 }

  condition:
    any of them
}