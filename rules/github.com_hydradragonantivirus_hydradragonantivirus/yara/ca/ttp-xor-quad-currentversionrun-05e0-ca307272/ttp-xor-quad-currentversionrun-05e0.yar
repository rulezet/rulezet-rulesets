rule TTP_XOR_QUAD_CurrentVersionRun_05e0 {
  strings:
    $key_05e0 = { 56 8f [2] 72 81 [2] 59 ad [2] 77 8f [2] 63 94 [2] 6c 8e [2] 72 93 [2] 70 92 [2] 6b 94 [2] 77 93 [2] 6b bc }

  condition:
    any of them
}