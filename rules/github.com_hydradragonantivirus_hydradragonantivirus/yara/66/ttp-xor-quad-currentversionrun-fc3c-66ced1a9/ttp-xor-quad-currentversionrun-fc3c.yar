rule TTP_XOR_QUAD_CurrentVersionRun_fc3c {
  strings:
    $key_fc3c = { af 53 [2] 8b 5d [2] a0 71 [2] 8e 53 [2] 9a 48 [2] 95 52 [2] 8b 4f [2] 89 4e [2] 92 48 [2] 8e 4f [2] 92 60 }

  condition:
    any of them
}