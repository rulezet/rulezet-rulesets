rule TTP_XOR_QUAD_CurrentVersionRun_ee28 {
  strings:
    $key_ee28 = { bd 47 [2] 99 49 [2] b2 65 [2] 9c 47 [2] 88 5c [2] 87 46 [2] 99 5b [2] 9b 5a [2] 80 5c [2] 9c 5b [2] 80 74 }

  condition:
    any of them
}