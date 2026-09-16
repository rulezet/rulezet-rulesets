rule TTP_XOR_QUAD_CurrentVersionRun_ee3d {
  strings:
    $key_ee3d = { bd 52 [2] 99 5c [2] b2 70 [2] 9c 52 [2] 88 49 [2] 87 53 [2] 99 4e [2] 9b 4f [2] 80 49 [2] 9c 4e [2] 80 61 }

  condition:
    any of them
}