rule TTP_XOR_QUAD_CurrentVersionRun_e92d {
  strings:
    $key_e92d = { ba 42 [2] 9e 4c [2] b5 60 [2] 9b 42 [2] 8f 59 [2] 80 43 [2] 9e 5e [2] 9c 5f [2] 87 59 [2] 9b 5e [2] 87 71 }

  condition:
    any of them
}