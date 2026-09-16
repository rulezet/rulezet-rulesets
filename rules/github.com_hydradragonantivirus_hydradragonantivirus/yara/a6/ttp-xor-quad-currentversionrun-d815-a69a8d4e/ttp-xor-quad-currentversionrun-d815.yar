rule TTP_XOR_QUAD_CurrentVersionRun_d815 {
  strings:
    $key_d815 = { 8b 7a [2] af 74 [2] 84 58 [2] aa 7a [2] be 61 [2] b1 7b [2] af 66 [2] ad 67 [2] b6 61 [2] aa 66 [2] b6 49 }

  condition:
    any of them
}