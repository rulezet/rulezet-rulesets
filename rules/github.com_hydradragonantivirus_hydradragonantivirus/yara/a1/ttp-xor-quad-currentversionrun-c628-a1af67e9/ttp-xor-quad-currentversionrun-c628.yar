rule TTP_XOR_QUAD_CurrentVersionRun_c628 {
  strings:
    $key_c628 = { 95 47 [2] b1 49 [2] 9a 65 [2] b4 47 [2] a0 5c [2] af 46 [2] b1 5b [2] b3 5a [2] a8 5c [2] b4 5b [2] a8 74 }

  condition:
    any of them
}