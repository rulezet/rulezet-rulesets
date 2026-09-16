rule TTP_XOR_QUAD_CurrentVersionRun_e9cf {
  strings:
    $key_e9cf = { ba a0 [2] 9e ae [2] b5 82 [2] 9b a0 [2] 8f bb [2] 80 a1 [2] 9e bc [2] 9c bd [2] 87 bb [2] 9b bc [2] 87 93 }

  condition:
    any of them
}