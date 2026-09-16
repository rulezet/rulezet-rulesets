rule TTP_XOR_QUAD_CurrentVersionRun_ee4b {
  strings:
    $key_ee4b = { bd 24 [2] 99 2a [2] b2 06 [2] 9c 24 [2] 88 3f [2] 87 25 [2] 99 38 [2] 9b 39 [2] 80 3f [2] 9c 38 [2] 80 17 }

  condition:
    any of them
}