rule TTP_XOR_QUAD_CurrentVersionRun_ee38 {
  strings:
    $key_ee38 = { bd 57 [2] 99 59 [2] b2 75 [2] 9c 57 [2] 88 4c [2] 87 56 [2] 99 4b [2] 9b 4a [2] 80 4c [2] 9c 4b [2] 80 64 }

  condition:
    any of them
}