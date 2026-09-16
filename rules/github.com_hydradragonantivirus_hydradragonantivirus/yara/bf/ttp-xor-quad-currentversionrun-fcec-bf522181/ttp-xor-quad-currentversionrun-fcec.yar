rule TTP_XOR_QUAD_CurrentVersionRun_fcec {
  strings:
    $key_fcec = { af 83 [2] 8b 8d [2] a0 a1 [2] 8e 83 [2] 9a 98 [2] 95 82 [2] 8b 9f [2] 89 9e [2] 92 98 [2] 8e 9f [2] 92 b0 }

  condition:
    any of them
}