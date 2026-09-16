rule TTP_XOR_QUAD_CurrentVersionRun_f8e0 {
  strings:
    $key_f8e0 = { ab 8f [2] 8f 81 [2] a4 ad [2] 8a 8f [2] 9e 94 [2] 91 8e [2] 8f 93 [2] 8d 92 [2] 96 94 [2] 8a 93 [2] 96 bc }

  condition:
    any of them
}