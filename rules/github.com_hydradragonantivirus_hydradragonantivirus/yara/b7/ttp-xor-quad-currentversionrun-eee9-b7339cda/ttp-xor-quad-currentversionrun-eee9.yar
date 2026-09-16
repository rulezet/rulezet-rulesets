rule TTP_XOR_QUAD_CurrentVersionRun_eee9 {
  strings:
    $key_eee9 = { bd 86 [2] 99 88 [2] b2 a4 [2] 9c 86 [2] 88 9d [2] 87 87 [2] 99 9a [2] 9b 9b [2] 80 9d [2] 9c 9a [2] 80 b5 }

  condition:
    any of them
}