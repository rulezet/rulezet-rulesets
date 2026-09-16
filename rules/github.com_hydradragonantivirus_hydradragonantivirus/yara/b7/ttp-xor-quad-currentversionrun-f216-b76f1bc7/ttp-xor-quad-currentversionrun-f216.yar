rule TTP_XOR_QUAD_CurrentVersionRun_f216 {
  strings:
    $key_f216 = { a1 79 [2] 85 77 [2] ae 5b [2] 80 79 [2] 94 62 [2] 9b 78 [2] 85 65 [2] 87 64 [2] 9c 62 [2] 80 65 [2] 9c 4a }

  condition:
    any of them
}