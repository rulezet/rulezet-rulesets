rule TTP_XOR_QUAD_CurrentVersionRun_ee48 {
  strings:
    $key_ee48 = { bd 27 [2] 99 29 [2] b2 05 [2] 9c 27 [2] 88 3c [2] 87 26 [2] 99 3b [2] 9b 3a [2] 80 3c [2] 9c 3b [2] 80 14 }

  condition:
    any of them
}