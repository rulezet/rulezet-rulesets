rule TTP_XOR_QUAD_CurrentVersionRun_ee13 {
  strings:
    $key_ee13 = { bd 7c [2] 99 72 [2] b2 5e [2] 9c 7c [2] 88 67 [2] 87 7d [2] 99 60 [2] 9b 61 [2] 80 67 [2] 9c 60 [2] 80 4f }

  condition:
    any of them
}