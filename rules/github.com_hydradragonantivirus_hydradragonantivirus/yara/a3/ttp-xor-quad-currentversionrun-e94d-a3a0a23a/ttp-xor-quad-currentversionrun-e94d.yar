rule TTP_XOR_QUAD_CurrentVersionRun_e94d {
  strings:
    $key_e94d = { ba 22 [2] 9e 2c [2] b5 00 [2] 9b 22 [2] 8f 39 [2] 80 23 [2] 9e 3e [2] 9c 3f [2] 87 39 [2] 9b 3e [2] 87 11 }

  condition:
    any of them
}