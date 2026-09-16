rule TTP_XOR_QUAD_CurrentVersionRun_ee25 {
  strings:
    $key_ee25 = { bd 4a [2] 99 44 [2] b2 68 [2] 9c 4a [2] 88 51 [2] 87 4b [2] 99 56 [2] 9b 57 [2] 80 51 [2] 9c 56 [2] 80 79 }

  condition:
    any of them
}