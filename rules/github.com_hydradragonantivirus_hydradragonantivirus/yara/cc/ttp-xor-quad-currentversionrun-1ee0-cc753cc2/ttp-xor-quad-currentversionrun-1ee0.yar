rule TTP_XOR_QUAD_CurrentVersionRun_1ee0 {
  strings:
    $key_1ee0 = { 4d 8f [2] 69 81 [2] 42 ad [2] 6c 8f [2] 78 94 [2] 77 8e [2] 69 93 [2] 6b 92 [2] 70 94 [2] 6c 93 [2] 70 bc }

  condition:
    any of them
}