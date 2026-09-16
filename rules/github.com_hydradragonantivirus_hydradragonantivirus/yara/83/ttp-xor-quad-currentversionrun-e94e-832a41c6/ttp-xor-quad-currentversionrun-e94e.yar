rule TTP_XOR_QUAD_CurrentVersionRun_e94e {
  strings:
    $key_e94e = { ba 21 [2] 9e 2f [2] b5 03 [2] 9b 21 [2] 8f 3a [2] 80 20 [2] 9e 3d [2] 9c 3c [2] 87 3a [2] 9b 3d [2] 87 12 }

  condition:
    any of them
}