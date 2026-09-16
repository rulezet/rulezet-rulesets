rule TTP_XOR_QUAD_CurrentVersionRun_ee06 {
  strings:
    $key_ee06 = { bd 69 [2] 99 67 [2] b2 4b [2] 9c 69 [2] 88 72 [2] 87 68 [2] 99 75 [2] 9b 74 [2] 80 72 [2] 9c 75 [2] 80 5a }

  condition:
    any of them
}