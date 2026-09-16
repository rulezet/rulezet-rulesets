rule TTP_XOR_QUAD_CurrentVersionRun_e816 {
  strings:
    $key_e816 = { bb 79 [2] 9f 77 [2] b4 5b [2] 9a 79 [2] 8e 62 [2] 81 78 [2] 9f 65 [2] 9d 64 [2] 86 62 [2] 9a 65 [2] 86 4a }

  condition:
    any of them
}