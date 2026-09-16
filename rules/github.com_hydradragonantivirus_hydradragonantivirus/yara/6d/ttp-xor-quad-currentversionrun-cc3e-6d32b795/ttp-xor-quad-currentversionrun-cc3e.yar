rule TTP_XOR_QUAD_CurrentVersionRun_cc3e {
  strings:
    $key_cc3e = { 9f 51 [2] bb 5f [2] 90 73 [2] be 51 [2] aa 4a [2] a5 50 [2] bb 4d [2] b9 4c [2] a2 4a [2] be 4d [2] a2 62 }

  condition:
    any of them
}