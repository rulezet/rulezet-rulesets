rule TTP_XOR_QUAD_CurrentVersionRun_ee58 {
  strings:
    $key_ee58 = { bd 37 [2] 99 39 [2] b2 15 [2] 9c 37 [2] 88 2c [2] 87 36 [2] 99 2b [2] 9b 2a [2] 80 2c [2] 9c 2b [2] 80 04 }

  condition:
    any of them
}