rule TTP_XOR_QUAD_CurrentVersionRun_e90f {
  strings:
    $key_e90f = { ba 60 [2] 9e 6e [2] b5 42 [2] 9b 60 [2] 8f 7b [2] 80 61 [2] 9e 7c [2] 9c 7d [2] 87 7b [2] 9b 7c [2] 87 53 }

  condition:
    any of them
}