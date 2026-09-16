rule TTP_XOR_QUAD_CurrentVersionRun_dd4f {
  strings:
    $key_dd4f = { 8e 20 [2] aa 2e [2] 81 02 [2] af 20 [2] bb 3b [2] b4 21 [2] aa 3c [2] a8 3d [2] b3 3b [2] af 3c [2] b3 13 }

  condition:
    any of them
}