rule TTP_XOR_QUAD_CurrentVersionRun_fc3e {
  strings:
    $key_fc3e = { af 51 [2] 8b 5f [2] a0 73 [2] 8e 51 [2] 9a 4a [2] 95 50 [2] 8b 4d [2] 89 4c [2] 92 4a [2] 8e 4d [2] 92 62 }

  condition:
    any of them
}