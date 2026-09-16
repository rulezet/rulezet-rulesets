rule TTP_XOR_QUAD_CurrentVersionRun_4ee0 {
  strings:
    $key_4ee0 = { 1d 8f [2] 39 81 [2] 12 ad [2] 3c 8f [2] 28 94 [2] 27 8e [2] 39 93 [2] 3b 92 [2] 20 94 [2] 3c 93 [2] 20 bc }

  condition:
    any of them
}