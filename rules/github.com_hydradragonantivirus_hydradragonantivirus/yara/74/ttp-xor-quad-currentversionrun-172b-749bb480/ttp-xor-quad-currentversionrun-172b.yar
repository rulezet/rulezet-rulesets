rule TTP_XOR_QUAD_CurrentVersionRun_172b {
  strings:
    $key_172b = { 44 44 [2] 60 4a [2] 4b 66 [2] 65 44 [2] 71 5f [2] 7e 45 [2] 60 58 [2] 62 59 [2] 79 5f [2] 65 58 [2] 79 77 }

  condition:
    any of them
}