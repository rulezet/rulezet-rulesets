rule TTP_XOR_QUAD_CurrentVersionRun_15e0 {
  strings:
    $key_15e0 = { 46 8f [2] 62 81 [2] 49 ad [2] 67 8f [2] 73 94 [2] 7c 8e [2] 62 93 [2] 60 92 [2] 7b 94 [2] 67 93 [2] 7b bc }

  condition:
    any of them
}