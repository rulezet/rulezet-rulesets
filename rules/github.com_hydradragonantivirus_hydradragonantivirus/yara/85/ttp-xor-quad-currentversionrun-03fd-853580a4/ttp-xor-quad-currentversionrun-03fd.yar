rule TTP_XOR_QUAD_CurrentVersionRun_03fd {
  strings:
    $key_03fd = { 50 92 [2] 74 9c [2] 5f b0 [2] 71 92 [2] 65 89 [2] 6a 93 [2] 74 8e [2] 76 8f [2] 6d 89 [2] 71 8e [2] 6d a1 }

  condition:
    any of them
}