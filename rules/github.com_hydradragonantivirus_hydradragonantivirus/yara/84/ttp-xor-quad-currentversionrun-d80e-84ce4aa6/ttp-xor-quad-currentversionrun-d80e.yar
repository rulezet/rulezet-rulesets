rule TTP_XOR_QUAD_CurrentVersionRun_d80e {
  strings:
    $key_d80e = { 8b 61 [2] af 6f [2] 84 43 [2] aa 61 [2] be 7a [2] b1 60 [2] af 7d [2] ad 7c [2] b6 7a [2] aa 7d [2] b6 52 }

  condition:
    any of them
}