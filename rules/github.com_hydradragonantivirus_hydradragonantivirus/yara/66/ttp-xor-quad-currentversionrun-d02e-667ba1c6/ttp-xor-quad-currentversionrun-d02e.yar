rule TTP_XOR_QUAD_CurrentVersionRun_d02e {
  strings:
    $key_d02e = { 83 41 [2] a7 4f [2] 8c 63 [2] a2 41 [2] b6 5a [2] b9 40 [2] a7 5d [2] a5 5c [2] be 5a [2] a2 5d [2] be 72 }

  condition:
    any of them
}