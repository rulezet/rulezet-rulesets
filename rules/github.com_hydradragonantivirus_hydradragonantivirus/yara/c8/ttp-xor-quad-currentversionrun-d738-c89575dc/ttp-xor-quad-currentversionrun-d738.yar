rule TTP_XOR_QUAD_CurrentVersionRun_d738 {
  strings:
    $key_d738 = { 84 57 [2] a0 59 [2] 8b 75 [2] a5 57 [2] b1 4c [2] be 56 [2] a0 4b [2] a2 4a [2] b9 4c [2] a5 4b [2] b9 64 }

  condition:
    any of them
}