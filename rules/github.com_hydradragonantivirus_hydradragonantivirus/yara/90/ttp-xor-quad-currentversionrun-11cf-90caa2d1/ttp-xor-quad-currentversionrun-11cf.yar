rule TTP_XOR_QUAD_CurrentVersionRun_11cf {
  strings:
    $key_11cf = { 42 a0 [2] 66 ae [2] 4d 82 [2] 63 a0 [2] 77 bb [2] 78 a1 [2] 66 bc [2] 64 bd [2] 7f bb [2] 63 bc [2] 7f 93 }

  condition:
    any of them
}