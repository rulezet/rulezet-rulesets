rule TTP_XOR_QUAD_CurrentVersionRun_ee35 {
  strings:
    $key_ee35 = { bd 5a [2] 99 54 [2] b2 78 [2] 9c 5a [2] 88 41 [2] 87 5b [2] 99 46 [2] 9b 47 [2] 80 41 [2] 9c 46 [2] 80 69 }

  condition:
    any of them
}