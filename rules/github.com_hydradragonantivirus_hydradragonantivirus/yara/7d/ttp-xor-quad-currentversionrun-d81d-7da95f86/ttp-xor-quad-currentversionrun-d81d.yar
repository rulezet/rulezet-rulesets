rule TTP_XOR_QUAD_CurrentVersionRun_d81d {
  strings:
    $key_d81d = { 8b 72 [2] af 7c [2] 84 50 [2] aa 72 [2] be 69 [2] b1 73 [2] af 6e [2] ad 6f [2] b6 69 [2] aa 6e [2] b6 41 }

  condition:
    any of them
}