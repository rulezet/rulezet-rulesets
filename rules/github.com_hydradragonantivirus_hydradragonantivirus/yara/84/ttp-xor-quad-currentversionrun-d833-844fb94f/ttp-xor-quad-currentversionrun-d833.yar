rule TTP_XOR_QUAD_CurrentVersionRun_d833 {
  strings:
    $key_d833 = { 8b 5c [2] af 52 [2] 84 7e [2] aa 5c [2] be 47 [2] b1 5d [2] af 40 [2] ad 41 [2] b6 47 [2] aa 40 [2] b6 6f }

  condition:
    any of them
}