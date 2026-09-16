rule TTP_XOR_QUAD_CurrentVersionRun_780d {
  strings:
    $key_780d = { 2b 62 [2] 0f 6c [2] 24 40 [2] 0a 62 [2] 1e 79 [2] 11 63 [2] 0f 7e [2] 0d 7f [2] 16 79 [2] 0a 7e [2] 16 51 }

  condition:
    any of them
}