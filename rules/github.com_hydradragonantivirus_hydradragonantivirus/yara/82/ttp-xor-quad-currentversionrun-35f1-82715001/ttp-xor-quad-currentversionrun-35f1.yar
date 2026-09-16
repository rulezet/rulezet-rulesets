rule TTP_XOR_QUAD_CurrentVersionRun_35f1 {
  strings:
    $key_35f1 = { 66 9e [2] 42 90 [2] 69 bc [2] 47 9e [2] 53 85 [2] 5c 9f [2] 42 82 [2] 40 83 [2] 5b 85 [2] 47 82 [2] 5b ad }

  condition:
    any of them
}