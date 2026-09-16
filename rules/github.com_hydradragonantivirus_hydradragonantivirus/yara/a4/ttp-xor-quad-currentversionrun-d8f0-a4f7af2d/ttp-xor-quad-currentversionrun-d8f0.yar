rule TTP_XOR_QUAD_CurrentVersionRun_d8f0 {
  strings:
    $key_d8f0 = { 8b 9f [2] af 91 [2] 84 bd [2] aa 9f [2] be 84 [2] b1 9e [2] af 83 [2] ad 82 [2] b6 84 [2] aa 83 [2] b6 ac }

  condition:
    any of them
}