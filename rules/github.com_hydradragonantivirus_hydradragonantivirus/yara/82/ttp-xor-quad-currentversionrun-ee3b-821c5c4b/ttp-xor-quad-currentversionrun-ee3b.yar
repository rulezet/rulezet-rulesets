rule TTP_XOR_QUAD_CurrentVersionRun_ee3b {
  strings:
    $key_ee3b = { bd 54 [2] 99 5a [2] b2 76 [2] 9c 54 [2] 88 4f [2] 87 55 [2] 99 48 [2] 9b 49 [2] 80 4f [2] 9c 48 [2] 80 67 }

  condition:
    any of them
}