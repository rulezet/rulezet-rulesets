rule TTP_XOR_QUAD_CurrentVersionRun_ee3f {
  strings:
    $key_ee3f = { bd 50 [2] 99 5e [2] b2 72 [2] 9c 50 [2] 88 4b [2] 87 51 [2] 99 4c [2] 9b 4d [2] 80 4b [2] 9c 4c [2] 80 63 }

  condition:
    any of them
}