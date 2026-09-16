rule TTP_XOR_QUAD_CurrentVersionRun_ee2b {
  strings:
    $key_ee2b = { bd 44 [2] 99 4a [2] b2 66 [2] 9c 44 [2] 88 5f [2] 87 45 [2] 99 58 [2] 9b 59 [2] 80 5f [2] 9c 58 [2] 80 77 }

  condition:
    any of them
}