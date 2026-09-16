rule TTP_XOR_QUAD_CurrentVersionRun_19cf {
  strings:
    $key_19cf = { 4a a0 [2] 6e ae [2] 45 82 [2] 6b a0 [2] 7f bb [2] 70 a1 [2] 6e bc [2] 6c bd [2] 77 bb [2] 6b bc [2] 77 93 }

  condition:
    any of them
}