rule TTP_XOR_QUAD_CurrentVersionRun_d862 {
  strings:
    $key_d862 = { 8b 0d [2] af 03 [2] 84 2f [2] aa 0d [2] be 16 [2] b1 0c [2] af 11 [2] ad 10 [2] b6 16 [2] aa 11 [2] b6 3e }

  condition:
    any of them
}