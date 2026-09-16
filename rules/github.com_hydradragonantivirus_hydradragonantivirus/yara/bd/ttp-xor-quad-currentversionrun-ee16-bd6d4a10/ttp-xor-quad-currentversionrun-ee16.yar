rule TTP_XOR_QUAD_CurrentVersionRun_ee16 {
  strings:
    $key_ee16 = { bd 79 [2] 99 77 [2] b2 5b [2] 9c 79 [2] 88 62 [2] 87 78 [2] 99 65 [2] 9b 64 [2] 80 62 [2] 9c 65 [2] 80 4a }

  condition:
    any of them
}