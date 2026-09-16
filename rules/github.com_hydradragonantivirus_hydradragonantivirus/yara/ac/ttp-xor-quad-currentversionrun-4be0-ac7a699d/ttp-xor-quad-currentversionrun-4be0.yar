rule TTP_XOR_QUAD_CurrentVersionRun_4be0 {
  strings:
    $key_4be0 = { 18 8f [2] 3c 81 [2] 17 ad [2] 39 8f [2] 2d 94 [2] 22 8e [2] 3c 93 [2] 3e 92 [2] 25 94 [2] 39 93 [2] 25 bc }

  condition:
    any of them
}