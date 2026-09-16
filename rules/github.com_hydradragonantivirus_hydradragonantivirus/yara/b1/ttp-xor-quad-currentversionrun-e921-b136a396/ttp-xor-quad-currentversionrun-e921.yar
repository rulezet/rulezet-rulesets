rule TTP_XOR_QUAD_CurrentVersionRun_e921 {
  strings:
    $key_e921 = { ba 4e [2] 9e 40 [2] b5 6c [2] 9b 4e [2] 8f 55 [2] 80 4f [2] 9e 52 [2] 9c 53 [2] 87 55 [2] 9b 52 [2] 87 7d }

  condition:
    any of them
}