rule TTP_XOR_QUAD_CurrentVersionRun_fc10 {
  strings:
    $key_fc10 = { af 7f [2] 8b 71 [2] a0 5d [2] 8e 7f [2] 9a 64 [2] 95 7e [2] 8b 63 [2] 89 62 [2] 92 64 [2] 8e 63 [2] 92 4c }

  condition:
    any of them
}