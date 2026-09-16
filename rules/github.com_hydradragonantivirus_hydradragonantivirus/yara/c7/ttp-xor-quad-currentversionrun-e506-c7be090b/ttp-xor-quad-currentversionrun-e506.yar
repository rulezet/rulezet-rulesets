rule TTP_XOR_QUAD_CurrentVersionRun_e506 {
  strings:
    $key_e506 = { b6 69 [2] 92 67 [2] b9 4b [2] 97 69 [2] 83 72 [2] 8c 68 [2] 92 75 [2] 90 74 [2] 8b 72 [2] 97 75 [2] 8b 5a }

  condition:
    any of them
}