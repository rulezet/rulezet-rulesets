rule TTP_XOR_QUAD_CurrentVersionRun_51fd {
  strings:
    $key_51fd = { 02 92 [2] 26 9c [2] 0d b0 [2] 23 92 [2] 37 89 [2] 38 93 [2] 26 8e [2] 24 8f [2] 3f 89 [2] 23 8e [2] 3f a1 }

  condition:
    any of them
}