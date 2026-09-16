rule TTP_XOR_QUAD_CurrentVersionRun_220d {
  strings:
    $key_220d = { 71 62 [2] 55 6c [2] 7e 40 [2] 50 62 [2] 44 79 [2] 4b 63 [2] 55 7e [2] 57 7f [2] 4c 79 [2] 50 7e [2] 4c 51 }

  condition:
    any of them
}