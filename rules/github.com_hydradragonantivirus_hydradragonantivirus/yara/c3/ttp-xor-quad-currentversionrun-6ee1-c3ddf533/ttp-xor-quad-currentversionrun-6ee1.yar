rule TTP_XOR_QUAD_CurrentVersionRun_6ee1 {
  strings:
    $key_6ee1 = { 3d 8e [2] 19 80 [2] 32 ac [2] 1c 8e [2] 08 95 [2] 07 8f [2] 19 92 [2] 1b 93 [2] 00 95 [2] 1c 92 [2] 00 bd }

  condition:
    any of them
}