rule TTP_XOR_QUAD_CurrentVersionRun_170d {
  strings:
    $key_170d = { 44 62 [2] 60 6c [2] 4b 40 [2] 65 62 [2] 71 79 [2] 7e 63 [2] 60 7e [2] 62 7f [2] 79 79 [2] 65 7e [2] 79 51 }

  condition:
    any of them
}