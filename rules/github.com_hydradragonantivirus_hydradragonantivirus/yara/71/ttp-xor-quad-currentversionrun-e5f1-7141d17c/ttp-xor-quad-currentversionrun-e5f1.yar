rule TTP_XOR_QUAD_CurrentVersionRun_e5f1 {
  strings:
    $key_e5f1 = { b6 9e [2] 92 90 [2] b9 bc [2] 97 9e [2] 83 85 [2] 8c 9f [2] 92 82 [2] 90 83 [2] 8b 85 [2] 97 82 [2] 8b ad }

  condition:
    any of them
}