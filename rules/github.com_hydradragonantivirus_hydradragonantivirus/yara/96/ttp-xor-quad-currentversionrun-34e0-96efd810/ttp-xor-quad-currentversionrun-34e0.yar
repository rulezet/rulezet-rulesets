rule TTP_XOR_QUAD_CurrentVersionRun_34e0 {
  strings:
    $key_34e0 = { 67 8f [2] 43 81 [2] 68 ad [2] 46 8f [2] 52 94 [2] 5d 8e [2] 43 93 [2] 41 92 [2] 5a 94 [2] 46 93 [2] 5a bc }

  condition:
    any of them
}