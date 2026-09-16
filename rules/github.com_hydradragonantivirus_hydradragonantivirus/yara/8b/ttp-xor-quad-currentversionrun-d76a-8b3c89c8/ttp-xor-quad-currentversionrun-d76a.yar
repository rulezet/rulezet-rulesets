rule TTP_XOR_QUAD_CurrentVersionRun_d76a {
  strings:
    $key_d76a = { 84 05 [2] a0 0b [2] 8b 27 [2] a5 05 [2] b1 1e [2] be 04 [2] a0 19 [2] a2 18 [2] b9 1e [2] a5 19 [2] b9 36 }

  condition:
    any of them
}