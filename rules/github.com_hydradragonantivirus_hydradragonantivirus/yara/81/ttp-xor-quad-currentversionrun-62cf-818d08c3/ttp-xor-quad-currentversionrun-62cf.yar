rule TTP_XOR_QUAD_CurrentVersionRun_62cf {
  strings:
    $key_62cf = { 31 a0 [2] 15 ae [2] 3e 82 [2] 10 a0 [2] 04 bb [2] 0b a1 [2] 15 bc [2] 17 bd [2] 0c bb [2] 10 bc [2] 0c 93 }

  condition:
    any of them
}