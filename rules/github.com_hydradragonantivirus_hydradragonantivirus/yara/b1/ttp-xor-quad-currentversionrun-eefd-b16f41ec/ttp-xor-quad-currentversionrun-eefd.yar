rule TTP_XOR_QUAD_CurrentVersionRun_eefd {
  strings:
    $key_eefd = { bd 92 [2] 99 9c [2] b2 b0 [2] 9c 92 [2] 88 89 [2] 87 93 [2] 99 8e [2] 9b 8f [2] 80 89 [2] 9c 8e [2] 80 a1 }

  condition:
    any of them
}