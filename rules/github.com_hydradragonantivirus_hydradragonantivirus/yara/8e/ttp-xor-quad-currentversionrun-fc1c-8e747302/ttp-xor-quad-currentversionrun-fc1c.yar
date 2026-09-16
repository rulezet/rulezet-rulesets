rule TTP_XOR_QUAD_CurrentVersionRun_fc1c {
  strings:
    $key_fc1c = { af 73 [2] 8b 7d [2] a0 51 [2] 8e 73 [2] 9a 68 [2] 95 72 [2] 8b 6f [2] 89 6e [2] 92 68 [2] 8e 6f [2] 92 40 }

  condition:
    any of them
}