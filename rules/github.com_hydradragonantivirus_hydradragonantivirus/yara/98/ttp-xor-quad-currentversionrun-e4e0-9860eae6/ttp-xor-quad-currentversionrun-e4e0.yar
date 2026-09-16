rule TTP_XOR_QUAD_CurrentVersionRun_e4e0 {
  strings:
    $key_e4e0 = { b7 8f [2] 93 81 [2] b8 ad [2] 96 8f [2] 82 94 [2] 8d 8e [2] 93 93 [2] 91 92 [2] 8a 94 [2] 96 93 [2] 8a bc }

  condition:
    any of them
}