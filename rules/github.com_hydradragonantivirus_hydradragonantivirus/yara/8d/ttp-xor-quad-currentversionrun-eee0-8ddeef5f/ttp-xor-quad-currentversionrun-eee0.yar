rule TTP_XOR_QUAD_CurrentVersionRun_eee0 {
  strings:
    $key_eee0 = { bd 8f [2] 99 81 [2] b2 ad [2] 9c 8f [2] 88 94 [2] 87 8e [2] 99 93 [2] 9b 92 [2] 80 94 [2] 9c 93 [2] 80 bc }

  condition:
    any of them
}