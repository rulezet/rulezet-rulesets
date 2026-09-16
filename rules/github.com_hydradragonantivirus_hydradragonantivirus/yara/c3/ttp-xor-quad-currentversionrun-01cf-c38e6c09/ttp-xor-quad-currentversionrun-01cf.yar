rule TTP_XOR_QUAD_CurrentVersionRun_01cf {
  strings:
    $key_01cf = { 52 a0 [2] 76 ae [2] 5d 82 [2] 73 a0 [2] 67 bb [2] 68 a1 [2] 76 bc [2] 74 bd [2] 6f bb [2] 73 bc [2] 6f 93 }

  condition:
    any of them
}