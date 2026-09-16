rule TTP_XOR_QUAD_CurrentVersionRun_dd1f {
  strings:
    $key_dd1f = { 8e 70 [2] aa 7e [2] 81 52 [2] af 70 [2] bb 6b [2] b4 71 [2] aa 6c [2] a8 6d [2] b3 6b [2] af 6c [2] b3 43 }

  condition:
    any of them
}