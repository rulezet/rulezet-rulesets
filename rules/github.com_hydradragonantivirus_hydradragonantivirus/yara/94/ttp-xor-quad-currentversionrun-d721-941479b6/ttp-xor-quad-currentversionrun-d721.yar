rule TTP_XOR_QUAD_CurrentVersionRun_d721 {
  strings:
    $key_d721 = { 84 4e [2] a0 40 [2] 8b 6c [2] a5 4e [2] b1 55 [2] be 4f [2] a0 52 [2] a2 53 [2] b9 55 [2] a5 52 [2] b9 7d }

  condition:
    any of them
}