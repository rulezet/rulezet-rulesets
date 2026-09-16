rule TTP_XOR_QUAD_CurrentVersionRun_fc06 {
  strings:
    $key_fc06 = { af 69 [2] 8b 67 [2] a0 4b [2] 8e 69 [2] 9a 72 [2] 95 68 [2] 8b 75 [2] 89 74 [2] 92 72 [2] 8e 75 [2] 92 5a }

  condition:
    any of them
}