rule TTP_XOR_QUAD_CurrentVersionRun_15f0 {
  strings:
    $key_15f0 = { 46 9f [2] 62 91 [2] 49 bd [2] 67 9f [2] 73 84 [2] 7c 9e [2] 62 83 [2] 60 82 [2] 7b 84 [2] 67 83 [2] 7b ac }

  condition:
    any of them
}