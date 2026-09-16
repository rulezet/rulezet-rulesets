rule TTP_XOR_QUAD_CurrentVersionRun_ccf9 {
  strings:
    $key_ccf9 = { 9f 96 [2] bb 98 [2] 90 b4 [2] be 96 [2] aa 8d [2] a5 97 [2] bb 8a [2] b9 8b [2] a2 8d [2] be 8a [2] a2 a5 }

  condition:
    any of them
}