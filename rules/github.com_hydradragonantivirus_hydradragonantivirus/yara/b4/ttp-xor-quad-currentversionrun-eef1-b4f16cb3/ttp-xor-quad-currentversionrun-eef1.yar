rule TTP_XOR_QUAD_CurrentVersionRun_eef1 {
  strings:
    $key_eef1 = { bd 9e [2] 99 90 [2] b2 bc [2] 9c 9e [2] 88 85 [2] 87 9f [2] 99 82 [2] 9b 83 [2] 80 85 [2] 9c 82 [2] 80 ad }

  condition:
    any of them
}