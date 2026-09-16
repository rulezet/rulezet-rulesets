rule TTP_XOR_QUAD_CurrentVersionRun_05cf {
  strings:
    $key_05cf = { 56 a0 [2] 72 ae [2] 59 82 [2] 77 a0 [2] 63 bb [2] 6c a1 [2] 72 bc [2] 70 bd [2] 6b bb [2] 77 bc [2] 6b 93 }

  condition:
    any of them
}