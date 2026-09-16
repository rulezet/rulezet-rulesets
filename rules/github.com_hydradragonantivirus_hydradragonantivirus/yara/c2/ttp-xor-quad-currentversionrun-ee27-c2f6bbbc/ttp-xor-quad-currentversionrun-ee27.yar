rule TTP_XOR_QUAD_CurrentVersionRun_ee27 {
  strings:
    $key_ee27 = { bd 48 [2] 99 46 [2] b2 6a [2] 9c 48 [2] 88 53 [2] 87 49 [2] 99 54 [2] 9b 55 [2] 80 53 [2] 9c 54 [2] 80 7b }

  condition:
    any of them
}