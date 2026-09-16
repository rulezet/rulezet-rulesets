rule TTP_XOR_QUAD_CurrentVersionRun_d824 {
  strings:
    $key_d824 = { 8b 4b [2] af 45 [2] 84 69 [2] aa 4b [2] be 50 [2] b1 4a [2] af 57 [2] ad 56 [2] b6 50 [2] aa 57 [2] b6 78 }

  condition:
    any of them
}