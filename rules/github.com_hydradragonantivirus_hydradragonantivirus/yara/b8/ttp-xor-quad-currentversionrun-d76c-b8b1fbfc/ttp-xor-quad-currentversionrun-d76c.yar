rule TTP_XOR_QUAD_CurrentVersionRun_d76c {
  strings:
    $key_d76c = { 84 03 [2] a0 0d [2] 8b 21 [2] a5 03 [2] b1 18 [2] be 02 [2] a0 1f [2] a2 1e [2] b9 18 [2] a5 1f [2] b9 30 }

  condition:
    any of them
}