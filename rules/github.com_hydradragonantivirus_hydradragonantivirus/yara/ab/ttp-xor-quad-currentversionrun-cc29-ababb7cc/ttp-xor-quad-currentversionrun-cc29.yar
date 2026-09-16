rule TTP_XOR_QUAD_CurrentVersionRun_cc29 {
  strings:
    $key_cc29 = { 9f 46 [2] bb 48 [2] 90 64 [2] be 46 [2] aa 5d [2] a5 47 [2] bb 5a [2] b9 5b [2] a2 5d [2] be 5a [2] a2 75 }

  condition:
    any of them
}