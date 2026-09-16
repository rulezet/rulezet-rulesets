rule TTP_XOR_QUAD_CurrentVersionRun_faf1 {
  strings:
    $key_faf1 = { a9 9e [2] 8d 90 [2] a6 bc [2] 88 9e [2] 9c 85 [2] 93 9f [2] 8d 82 [2] 8f 83 [2] 94 85 [2] 88 82 [2] 94 ad }

  condition:
    any of them
}