rule TTP_XOR_QUAD_CurrentVersionRun_172a {
  strings:
    $key_172a = { 44 45 [2] 60 4b [2] 4b 67 [2] 65 45 [2] 71 5e [2] 7e 44 [2] 60 59 [2] 62 58 [2] 79 5e [2] 65 59 [2] 79 76 }

  condition:
    any of them
}