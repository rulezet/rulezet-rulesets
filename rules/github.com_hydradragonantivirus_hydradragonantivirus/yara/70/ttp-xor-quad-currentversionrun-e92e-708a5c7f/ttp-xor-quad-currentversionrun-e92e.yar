rule TTP_XOR_QUAD_CurrentVersionRun_e92e {
  strings:
    $key_e92e = { ba 41 [2] 9e 4f [2] b5 63 [2] 9b 41 [2] 8f 5a [2] 80 40 [2] 9e 5d [2] 9c 5c [2] 87 5a [2] 9b 5d [2] 87 72 }

  condition:
    any of them
}