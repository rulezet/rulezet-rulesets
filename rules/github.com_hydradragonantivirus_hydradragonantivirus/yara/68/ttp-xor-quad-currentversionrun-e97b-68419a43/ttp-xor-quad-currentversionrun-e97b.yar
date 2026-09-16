rule TTP_XOR_QUAD_CurrentVersionRun_e97b {
  strings:
    $key_e97b = { ba 14 [2] 9e 1a [2] b5 36 [2] 9b 14 [2] 8f 0f [2] 80 15 [2] 9e 08 [2] 9c 09 [2] 87 0f [2] 9b 08 [2] 87 27 }

  condition:
    any of them
}