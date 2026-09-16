rule TTP_XOR_QUAD_CurrentVersionRun_d822 {
  strings:
    $key_d822 = { 8b 4d [2] af 43 [2] 84 6f [2] aa 4d [2] be 56 [2] b1 4c [2] af 51 [2] ad 50 [2] b6 56 [2] aa 51 [2] b6 7e }

  condition:
    any of them
}