rule TTP_XOR_QUAD_CurrentVersionRun_e93c {
  strings:
    $key_e93c = { ba 53 [2] 9e 5d [2] b5 71 [2] 9b 53 [2] 8f 48 [2] 80 52 [2] 9e 4f [2] 9c 4e [2] 87 48 [2] 9b 4f [2] 87 60 }

  condition:
    any of them
}