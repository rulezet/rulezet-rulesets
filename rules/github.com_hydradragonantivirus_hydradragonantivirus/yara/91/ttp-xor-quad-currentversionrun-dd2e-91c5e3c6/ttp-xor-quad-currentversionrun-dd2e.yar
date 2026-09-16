rule TTP_XOR_QUAD_CurrentVersionRun_dd2e {
  strings:
    $key_dd2e = { 8e 41 [2] aa 4f [2] 81 63 [2] af 41 [2] bb 5a [2] b4 40 [2] aa 5d [2] a8 5c [2] b3 5a [2] af 5d [2] b3 72 }

  condition:
    any of them
}