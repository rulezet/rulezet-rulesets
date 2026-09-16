rule TTP_XOR_QUAD_CurrentVersionRun_e94c {
  strings:
    $key_e94c = { ba 23 [2] 9e 2d [2] b5 01 [2] 9b 23 [2] 8f 38 [2] 80 22 [2] 9e 3f [2] 9c 3e [2] 87 38 [2] 9b 3f [2] 87 10 }

  condition:
    any of them
}