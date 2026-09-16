rule TTP_XOR_QUAD_CurrentVersionRun_73fd {
  strings:
    $key_73fd = { 20 92 [2] 04 9c [2] 2f b0 [2] 01 92 [2] 15 89 [2] 1a 93 [2] 04 8e [2] 06 8f [2] 1d 89 [2] 01 8e [2] 1d a1 }

  condition:
    any of them
}