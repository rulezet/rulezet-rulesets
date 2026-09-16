rule TTP_XOR_QUAD_CurrentVersionRun_0be0 {
  strings:
    $key_0be0 = { 58 8f [2] 7c 81 [2] 57 ad [2] 79 8f [2] 6d 94 [2] 62 8e [2] 7c 93 [2] 7e 92 [2] 65 94 [2] 79 93 [2] 65 bc }

  condition:
    any of them
}