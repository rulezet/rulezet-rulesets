rule TTP_XOR_QUAD_CurrentVersionRun_fee0 {
  strings:
    $key_fee0 = { ad 8f [2] 89 81 [2] a2 ad [2] 8c 8f [2] 98 94 [2] 97 8e [2] 89 93 [2] 8b 92 [2] 90 94 [2] 8c 93 [2] 90 bc }

  condition:
    any of them
}