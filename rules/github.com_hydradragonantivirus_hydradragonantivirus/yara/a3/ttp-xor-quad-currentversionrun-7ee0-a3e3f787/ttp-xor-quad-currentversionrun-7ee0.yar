rule TTP_XOR_QUAD_CurrentVersionRun_7ee0 {
  strings:
    $key_7ee0 = { 2d 8f [2] 09 81 [2] 22 ad [2] 0c 8f [2] 18 94 [2] 17 8e [2] 09 93 [2] 0b 92 [2] 10 94 [2] 0c 93 [2] 10 bc }

  condition:
    any of them
}