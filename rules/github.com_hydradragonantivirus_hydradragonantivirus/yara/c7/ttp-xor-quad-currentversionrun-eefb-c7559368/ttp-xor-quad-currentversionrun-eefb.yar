rule TTP_XOR_QUAD_CurrentVersionRun_eefb {
  strings:
    $key_eefb = { bd 94 [2] 99 9a [2] b2 b6 [2] 9c 94 [2] 88 8f [2] 87 95 [2] 99 88 [2] 9b 89 [2] 80 8f [2] 9c 88 [2] 80 a7 }

  condition:
    any of them
}