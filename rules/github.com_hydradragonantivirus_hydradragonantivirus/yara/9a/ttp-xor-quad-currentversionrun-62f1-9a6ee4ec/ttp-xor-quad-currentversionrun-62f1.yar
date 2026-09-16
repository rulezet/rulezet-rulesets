rule TTP_XOR_QUAD_CurrentVersionRun_62f1 {
  strings:
    $key_62f1 = { 31 9e [2] 15 90 [2] 3e bc [2] 10 9e [2] 04 85 [2] 0b 9f [2] 15 82 [2] 17 83 [2] 0c 85 [2] 10 82 [2] 0c ad }

  condition:
    any of them
}