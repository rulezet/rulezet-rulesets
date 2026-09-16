rule TTP_XOR_QUAD_CurrentVersionRun_d719 {
  strings:
    $key_d719 = { 84 76 [2] a0 78 [2] 8b 54 [2] a5 76 [2] b1 6d [2] be 77 [2] a0 6a [2] a2 6b [2] b9 6d [2] a5 6a [2] b9 45 }

  condition:
    any of them
}