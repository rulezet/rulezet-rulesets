rule TTP_XOR_QUAD_CurrentVersionRun_e516 {
  strings:
    $key_e516 = { b6 79 [2] 92 77 [2] b9 5b [2] 97 79 [2] 83 62 [2] 8c 78 [2] 92 65 [2] 90 64 [2] 8b 62 [2] 97 65 [2] 8b 4a }

  condition:
    any of them
}