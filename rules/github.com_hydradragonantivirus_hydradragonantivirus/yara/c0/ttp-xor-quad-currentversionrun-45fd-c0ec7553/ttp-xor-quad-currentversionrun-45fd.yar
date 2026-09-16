rule TTP_XOR_QUAD_CurrentVersionRun_45fd {
  strings:
    $key_45fd = { 16 92 [2] 32 9c [2] 19 b0 [2] 37 92 [2] 23 89 [2] 2c 93 [2] 32 8e [2] 30 8f [2] 2b 89 [2] 37 8e [2] 2b a1 }

  condition:
    any of them
}