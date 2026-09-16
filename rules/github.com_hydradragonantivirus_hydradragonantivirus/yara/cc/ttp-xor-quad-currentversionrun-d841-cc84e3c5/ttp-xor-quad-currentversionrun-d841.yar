rule TTP_XOR_QUAD_CurrentVersionRun_d841 {
  strings:
    $key_d841 = { 8b 2e [2] af 20 [2] 84 0c [2] aa 2e [2] be 35 [2] b1 2f [2] af 32 [2] ad 33 [2] b6 35 [2] aa 32 [2] b6 1d }

  condition:
    any of them
}