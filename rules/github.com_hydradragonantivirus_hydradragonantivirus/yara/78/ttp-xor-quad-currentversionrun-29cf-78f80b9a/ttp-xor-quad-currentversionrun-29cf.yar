rule TTP_XOR_QUAD_CurrentVersionRun_29cf {
  strings:
    $key_29cf = { 7a a0 [2] 5e ae [2] 75 82 [2] 5b a0 [2] 4f bb [2] 40 a1 [2] 5e bc [2] 5c bd [2] 47 bb [2] 5b bc [2] 47 93 }

  condition:
    any of them
}