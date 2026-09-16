rule TTP_XOR_QUAD_CurrentVersionRun_dd35 {
  strings:
    $key_dd35 = { 8e 5a [2] aa 54 [2] 81 78 [2] af 5a [2] bb 41 [2] b4 5b [2] aa 46 [2] a8 47 [2] b3 41 [2] af 46 [2] b3 69 }

  condition:
    any of them
}