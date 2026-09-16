rule TTP_XOR_QUAD_CurrentVersionRun_dd1e {
  strings:
    $key_dd1e = { 8e 71 [2] aa 7f [2] 81 53 [2] af 71 [2] bb 6a [2] b4 70 [2] aa 6d [2] a8 6c [2] b3 6a [2] af 6d [2] b3 42 }

  condition:
    any of them
}