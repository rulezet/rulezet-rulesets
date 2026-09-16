rule TTP_XOR_QUAD_CurrentVersionRun_6ee0 {
  strings:
    $key_6ee0 = { 3d 8f [2] 19 81 [2] 32 ad [2] 1c 8f [2] 08 94 [2] 07 8e [2] 19 93 [2] 1b 92 [2] 00 94 [2] 1c 93 [2] 00 bc }

  condition:
    any of them
}