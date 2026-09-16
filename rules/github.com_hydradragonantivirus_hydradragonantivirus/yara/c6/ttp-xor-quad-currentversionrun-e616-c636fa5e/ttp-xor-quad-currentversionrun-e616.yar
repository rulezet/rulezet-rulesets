rule TTP_XOR_QUAD_CurrentVersionRun_e616 {
  strings:
    $key_e616 = { b5 79 [2] 91 77 [2] ba 5b [2] 94 79 [2] 80 62 [2] 8f 78 [2] 91 65 [2] 93 64 [2] 88 62 [2] 94 65 [2] 88 4a }

  condition:
    any of them
}