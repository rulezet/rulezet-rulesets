rule TTP_XOR_QUAD_CurrentVersionRun_ccf0 {
  strings:
    $key_ccf0 = { 9f 9f [2] bb 91 [2] 90 bd [2] be 9f [2] aa 84 [2] a5 9e [2] bb 83 [2] b9 82 [2] a2 84 [2] be 83 [2] a2 ac }

  condition:
    any of them
}