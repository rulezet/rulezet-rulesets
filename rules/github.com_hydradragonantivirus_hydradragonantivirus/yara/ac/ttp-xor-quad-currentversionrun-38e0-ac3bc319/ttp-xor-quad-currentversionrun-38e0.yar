rule TTP_XOR_QUAD_CurrentVersionRun_38e0 {
  strings:
    $key_38e0 = { 6b 8f [2] 4f 81 [2] 64 ad [2] 4a 8f [2] 5e 94 [2] 51 8e [2] 4f 93 [2] 4d 92 [2] 56 94 [2] 4a 93 [2] 56 bc }

  condition:
    any of them
}