rule TTP_XOR_QUAD_CurrentVersionRun_f6e0 {
  strings:
    $key_f6e0 = { a5 8f [2] 81 81 [2] aa ad [2] 84 8f [2] 90 94 [2] 9f 8e [2] 81 93 [2] 83 92 [2] 98 94 [2] 84 93 [2] 98 bc }

  condition:
    any of them
}