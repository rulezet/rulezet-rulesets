rule TTP_XOR_QUAD_CurrentVersionRun_ee2a {
  strings:
    $key_ee2a = { bd 45 [2] 99 4b [2] b2 67 [2] 9c 45 [2] 88 5e [2] 87 44 [2] 99 59 [2] 9b 58 [2] 80 5e [2] 9c 59 [2] 80 76 }

  condition:
    any of them
}