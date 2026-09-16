rule TTP_XOR_QUAD_CurrentVersionRun_ccf8 {
  strings:
    $key_ccf8 = { 9f 97 [2] bb 99 [2] 90 b5 [2] be 97 [2] aa 8c [2] a5 96 [2] bb 8b [2] b9 8a [2] a2 8c [2] be 8b [2] a2 a4 }

  condition:
    any of them
}