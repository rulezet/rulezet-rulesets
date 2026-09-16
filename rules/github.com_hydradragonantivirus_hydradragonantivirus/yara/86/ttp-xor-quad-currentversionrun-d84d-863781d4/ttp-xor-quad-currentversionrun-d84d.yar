rule TTP_XOR_QUAD_CurrentVersionRun_d84d {
  strings:
    $key_d84d = { 8b 22 [2] af 2c [2] 84 00 [2] aa 22 [2] be 39 [2] b1 23 [2] af 3e [2] ad 3f [2] b6 39 [2] aa 3e [2] b6 11 }

  condition:
    any of them
}