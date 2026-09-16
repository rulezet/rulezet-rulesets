rule TTP_XOR_QUAD_CurrentVersionRun_14fd {
  strings:
    $key_14fd = { 47 92 [2] 63 9c [2] 48 b0 [2] 66 92 [2] 72 89 [2] 7d 93 [2] 63 8e [2] 61 8f [2] 7a 89 [2] 66 8e [2] 7a a1 }

  condition:
    any of them
}