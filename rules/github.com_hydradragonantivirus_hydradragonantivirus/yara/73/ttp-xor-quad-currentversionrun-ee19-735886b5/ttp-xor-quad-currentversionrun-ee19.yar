rule TTP_XOR_QUAD_CurrentVersionRun_ee19 {
  strings:
    $key_ee19 = { bd 76 [2] 99 78 [2] b2 54 [2] 9c 76 [2] 88 6d [2] 87 77 [2] 99 6a [2] 9b 6b [2] 80 6d [2] 9c 6a [2] 80 45 }

  condition:
    any of them
}