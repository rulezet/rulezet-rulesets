rule TTP_XOR_QUAD_CurrentVersionRun_d83e {
  strings:
    $key_d83e = { 8b 51 [2] af 5f [2] 84 73 [2] aa 51 [2] be 4a [2] b1 50 [2] af 4d [2] ad 4c [2] b6 4a [2] aa 4d [2] b6 62 }

  condition:
    any of them
}