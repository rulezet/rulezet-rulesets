rule TTP_XOR_QUAD_CurrentVersionRun_ed02 {
  strings:
    $key_ed02 = { be 6d [2] 9a 63 [2] b1 4f [2] 9f 6d [2] 8b 76 [2] 84 6c [2] 9a 71 [2] 98 70 [2] 83 76 [2] 9f 71 [2] 83 5e }

  condition:
    any of them
}