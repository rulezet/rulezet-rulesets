rule TTP_XOR_QUAD_CurrentVersionRun_fc0f {
  strings:
    $key_fc0f = { af 60 [2] 8b 6e [2] a0 42 [2] 8e 60 [2] 9a 7b [2] 95 61 [2] 8b 7c [2] 89 7d [2] 92 7b [2] 8e 7c [2] 92 53 }

  condition:
    any of them
}