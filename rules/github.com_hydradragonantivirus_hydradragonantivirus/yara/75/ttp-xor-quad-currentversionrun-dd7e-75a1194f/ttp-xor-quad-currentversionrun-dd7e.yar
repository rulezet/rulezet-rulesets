rule TTP_XOR_QUAD_CurrentVersionRun_dd7e {
  strings:
    $key_dd7e = { 8e 11 [2] aa 1f [2] 81 33 [2] af 11 [2] bb 0a [2] b4 10 [2] aa 0d [2] a8 0c [2] b3 0a [2] af 0d [2] b3 22 }

  condition:
    any of them
}