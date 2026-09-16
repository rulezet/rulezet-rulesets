rule TTP_XOR_QUAD_CurrentVersionRun_edff {
  strings:
    $key_edff = { be 90 [2] 9a 9e [2] b1 b2 [2] 9f 90 [2] 8b 8b [2] 84 91 [2] 9a 8c [2] 98 8d [2] 83 8b [2] 9f 8c [2] 83 a3 }

  condition:
    any of them
}