rule TTP_XOR_QUAD_CurrentVersionRun_6e01 {
  strings:
    $key_6e01 = { 3d 6e [2] 19 60 [2] 32 4c [2] 1c 6e [2] 08 75 [2] 07 6f [2] 19 72 [2] 1b 73 [2] 00 75 [2] 1c 72 [2] 00 5d }

  condition:
    any of them
}