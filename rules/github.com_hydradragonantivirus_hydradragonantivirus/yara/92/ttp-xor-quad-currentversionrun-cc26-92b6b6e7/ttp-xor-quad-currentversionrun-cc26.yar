rule TTP_XOR_QUAD_CurrentVersionRun_cc26 {
  strings:
    $key_cc26 = { 9f 49 [2] bb 47 [2] 90 6b [2] be 49 [2] aa 52 [2] a5 48 [2] bb 55 [2] b9 54 [2] a2 52 [2] be 55 [2] a2 7a }

  condition:
    any of them
}