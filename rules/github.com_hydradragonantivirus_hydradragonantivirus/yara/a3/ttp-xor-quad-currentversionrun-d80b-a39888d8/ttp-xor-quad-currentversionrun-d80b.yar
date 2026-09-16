rule TTP_XOR_QUAD_CurrentVersionRun_d80b {
  strings:
    $key_d80b = { 8b 64 [2] af 6a [2] 84 46 [2] aa 64 [2] be 7f [2] b1 65 [2] af 78 [2] ad 79 [2] b6 7f [2] aa 78 [2] b6 57 }

  condition:
    any of them
}