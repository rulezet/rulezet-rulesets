rule TTP_XOR_QUAD_CurrentVersionRun_ee26 {
  strings:
    $key_ee26 = { bd 49 [2] 99 47 [2] b2 6b [2] 9c 49 [2] 88 52 [2] 87 48 [2] 99 55 [2] 9b 54 [2] 80 52 [2] 9c 55 [2] 80 7a }

  condition:
    any of them
}