rule TTP_XOR_QUAD_CurrentVersionRun_7816 {
  strings:
    $key_7816 = { 2b 79 [2] 0f 77 [2] 24 5b [2] 0a 79 [2] 1e 62 [2] 11 78 [2] 0f 65 [2] 0d 64 [2] 16 62 [2] 0a 65 [2] 16 4a }

  condition:
    any of them
}