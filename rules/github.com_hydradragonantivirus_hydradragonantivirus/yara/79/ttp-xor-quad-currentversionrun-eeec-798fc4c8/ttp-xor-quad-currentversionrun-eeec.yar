rule TTP_XOR_QUAD_CurrentVersionRun_eeec {
  strings:
    $key_eeec = { bd 83 [2] 99 8d [2] b2 a1 [2] 9c 83 [2] 88 98 [2] 87 82 [2] 99 9f [2] 9b 9e [2] 80 98 [2] 9c 9f [2] 80 b0 }

  condition:
    any of them
}