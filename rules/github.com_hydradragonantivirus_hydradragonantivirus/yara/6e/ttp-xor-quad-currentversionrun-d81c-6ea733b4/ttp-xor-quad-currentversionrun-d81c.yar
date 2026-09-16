rule TTP_XOR_QUAD_CurrentVersionRun_d81c {
  strings:
    $key_d81c = { 8b 73 [2] af 7d [2] 84 51 [2] aa 73 [2] be 68 [2] b1 72 [2] af 6f [2] ad 6e [2] b6 68 [2] aa 6f [2] b6 40 }

  condition:
    any of them
}