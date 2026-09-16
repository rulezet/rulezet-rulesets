rule TTP_XOR_QUAD_CurrentVersionRun_d70e {
  strings:
    $key_d70e = { 84 61 [2] a0 6f [2] 8b 43 [2] a5 61 [2] b1 7a [2] be 60 [2] a0 7d [2] a2 7c [2] b9 7a [2] a5 7d [2] b9 52 }

  condition:
    any of them
}