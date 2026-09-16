rule TTP_XOR_QUAD_CurrentVersionRun_3ae0 {
  strings:
    $key_3ae0 = { 69 8f [2] 4d 81 [2] 66 ad [2] 48 8f [2] 5c 94 [2] 53 8e [2] 4d 93 [2] 4f 92 [2] 54 94 [2] 48 93 [2] 54 bc }

  condition:
    any of them
}