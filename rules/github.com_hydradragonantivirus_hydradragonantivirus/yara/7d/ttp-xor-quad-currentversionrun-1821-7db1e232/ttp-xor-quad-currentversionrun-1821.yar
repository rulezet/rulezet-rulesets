rule TTP_XOR_QUAD_CurrentVersionRun_1821 {
  strings:
    $key_1821 = { 4b 4e [2] 6f 40 [2] 44 6c [2] 6a 4e [2] 7e 55 [2] 71 4f [2] 6f 52 [2] 6d 53 [2] 76 55 [2] 6a 52 [2] 76 7d }

  condition:
    any of them
}