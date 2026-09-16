rule TTP_XOR_QUAD_CurrentVersionRun_eee2 {
  strings:
    $key_eee2 = { bd 8d [2] 99 83 [2] b2 af [2] 9c 8d [2] 88 96 [2] 87 8c [2] 99 91 [2] 9b 90 [2] 80 96 [2] 9c 91 [2] 80 be }

  condition:
    any of them
}