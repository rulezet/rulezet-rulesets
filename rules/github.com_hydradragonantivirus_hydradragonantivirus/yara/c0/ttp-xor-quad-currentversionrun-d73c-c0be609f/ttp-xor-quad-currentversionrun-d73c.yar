rule TTP_XOR_QUAD_CurrentVersionRun_d73c {
  strings:
    $key_d73c = { 84 53 [2] a0 5d [2] 8b 71 [2] a5 53 [2] b1 48 [2] be 52 [2] a0 4f [2] a2 4e [2] b9 48 [2] a5 4f [2] b9 60 }

  condition:
    any of them
}