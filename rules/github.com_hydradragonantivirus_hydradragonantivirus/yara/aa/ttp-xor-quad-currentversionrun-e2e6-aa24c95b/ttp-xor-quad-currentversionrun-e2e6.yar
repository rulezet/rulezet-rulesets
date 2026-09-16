rule TTP_XOR_QUAD_CurrentVersionRun_e2e6 {
  strings:
    $key_e2e6 = { b1 89 [2] 95 87 [2] be ab [2] 90 89 [2] 84 92 [2] 8b 88 [2] 95 95 [2] 97 94 [2] 8c 92 [2] 90 95 [2] 8c ba }

  condition:
    any of them
}