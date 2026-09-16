rule TTP_XOR_QUAD_CurrentVersionRun_d748 {
  strings:
    $key_d748 = { 84 27 [2] a0 29 [2] 8b 05 [2] a5 27 [2] b1 3c [2] be 26 [2] a0 3b [2] a2 3a [2] b9 3c [2] a5 3b [2] b9 14 }

  condition:
    any of them
}