rule TTP_XOR_QUAD_CurrentVersionRun_edf3 {
  strings:
    $key_edf3 = { be 9c [2] 9a 92 [2] b1 be [2] 9f 9c [2] 8b 87 [2] 84 9d [2] 9a 80 [2] 98 81 [2] 83 87 [2] 9f 80 [2] 83 af }

  condition:
    any of them
}