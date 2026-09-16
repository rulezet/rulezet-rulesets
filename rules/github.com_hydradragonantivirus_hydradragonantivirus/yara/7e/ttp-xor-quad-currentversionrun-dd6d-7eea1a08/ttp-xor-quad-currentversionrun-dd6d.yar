rule TTP_XOR_QUAD_CurrentVersionRun_dd6d {
  strings:
    $key_dd6d = { 8e 02 [2] aa 0c [2] 81 20 [2] af 02 [2] bb 19 [2] b4 03 [2] aa 1e [2] a8 1f [2] b3 19 [2] af 1e [2] b3 31 }

  condition:
    any of them
}