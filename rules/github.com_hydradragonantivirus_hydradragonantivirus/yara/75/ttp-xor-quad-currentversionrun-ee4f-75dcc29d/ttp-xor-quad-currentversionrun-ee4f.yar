rule TTP_XOR_QUAD_CurrentVersionRun_ee4f {
  strings:
    $key_ee4f = { bd 20 [2] 99 2e [2] b2 02 [2] 9c 20 [2] 88 3b [2] 87 21 [2] 99 3c [2] 9b 3d [2] 80 3b [2] 9c 3c [2] 80 13 }

  condition:
    any of them
}