rule TTP_XOR_QUAD_CurrentVersionRun_d728 {
  strings:
    $key_d728 = { 84 47 [2] a0 49 [2] 8b 65 [2] a5 47 [2] b1 5c [2] be 46 [2] a0 5b [2] a2 5a [2] b9 5c [2] a5 5b [2] b9 74 }

  condition:
    any of them
}