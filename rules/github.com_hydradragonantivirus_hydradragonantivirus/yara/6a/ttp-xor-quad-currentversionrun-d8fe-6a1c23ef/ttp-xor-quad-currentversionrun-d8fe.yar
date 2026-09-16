rule TTP_XOR_QUAD_CurrentVersionRun_d8fe {
  strings:
    $key_d8fe = { 8b 91 [2] af 9f [2] 84 b3 [2] aa 91 [2] be 8a [2] b1 90 [2] af 8d [2] ad 8c [2] b6 8a [2] aa 8d [2] b6 a2 }

  condition:
    any of them
}