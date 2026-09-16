rule TTP_XOR_QUAD_CurrentVersionRun_d705 {
  strings:
    $key_d705 = { 84 6a [2] a0 64 [2] 8b 48 [2] a5 6a [2] b1 71 [2] be 6b [2] a0 76 [2] a2 77 [2] b9 71 [2] a5 76 [2] b9 59 }

  condition:
    any of them
}