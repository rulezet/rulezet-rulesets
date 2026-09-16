rule TTP_XOR_QUAD_CurrentVersionRun_2be0 {
  strings:
    $key_2be0 = { 78 8f [2] 5c 81 [2] 77 ad [2] 59 8f [2] 4d 94 [2] 42 8e [2] 5c 93 [2] 5e 92 [2] 45 94 [2] 59 93 [2] 45 bc }

  condition:
    any of them
}