rule TTP_XOR_QUAD_CurrentVersionRun_ee2e {
  strings:
    $key_ee2e = { bd 41 [2] 99 4f [2] b2 63 [2] 9c 41 [2] 88 5a [2] 87 40 [2] 99 5d [2] 9b 5c [2] 80 5a [2] 9c 5d [2] 80 72 }

  condition:
    any of them
}