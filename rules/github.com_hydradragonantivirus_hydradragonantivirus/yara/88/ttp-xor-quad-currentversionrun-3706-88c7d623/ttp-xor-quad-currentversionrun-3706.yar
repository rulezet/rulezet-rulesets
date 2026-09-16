rule TTP_XOR_QUAD_CurrentVersionRun_3706 {
  strings:
    $key_3706 = { 64 69 [2] 40 67 [2] 6b 4b [2] 45 69 [2] 51 72 [2] 5e 68 [2] 40 75 [2] 42 74 [2] 59 72 [2] 45 75 [2] 59 5a }

  condition:
    any of them
}