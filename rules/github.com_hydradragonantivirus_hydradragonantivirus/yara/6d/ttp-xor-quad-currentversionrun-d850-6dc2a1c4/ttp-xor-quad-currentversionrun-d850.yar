rule TTP_XOR_QUAD_CurrentVersionRun_d850 {
  strings:
    $key_d850 = { 8b 3f [2] af 31 [2] 84 1d [2] aa 3f [2] be 24 [2] b1 3e [2] af 23 [2] ad 22 [2] b6 24 [2] aa 23 [2] b6 0c }

  condition:
    any of them
}