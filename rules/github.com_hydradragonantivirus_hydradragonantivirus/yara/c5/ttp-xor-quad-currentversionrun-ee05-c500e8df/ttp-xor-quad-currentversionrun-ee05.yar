rule TTP_XOR_QUAD_CurrentVersionRun_ee05 {
  strings:
    $key_ee05 = { bd 6a [2] 99 64 [2] b2 48 [2] 9c 6a [2] 88 71 [2] 87 6b [2] 99 76 [2] 9b 77 [2] 80 71 [2] 9c 76 [2] 80 59 }

  condition:
    any of them
}