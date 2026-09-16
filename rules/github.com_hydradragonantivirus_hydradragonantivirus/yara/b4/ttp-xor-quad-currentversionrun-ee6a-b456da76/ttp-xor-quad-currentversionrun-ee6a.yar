rule TTP_XOR_QUAD_CurrentVersionRun_ee6a {
  strings:
    $key_ee6a = { bd 05 [2] 99 0b [2] b2 27 [2] 9c 05 [2] 88 1e [2] 87 04 [2] 99 19 [2] 9b 18 [2] 80 1e [2] 9c 19 [2] 80 36 }

  condition:
    any of them
}