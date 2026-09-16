rule TTP_XOR_QUAD_CurrentVersionRun_62f0 {
  strings:
    $key_62f0 = { 31 9f [2] 15 91 [2] 3e bd [2] 10 9f [2] 04 84 [2] 0b 9e [2] 15 83 [2] 17 82 [2] 0c 84 [2] 10 83 [2] 0c ac }

  condition:
    any of them
}