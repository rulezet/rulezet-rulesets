rule TTP_XOR_QUAD_CurrentVersionRun_176d {
  strings:
    $key_176d = { 44 02 [2] 60 0c [2] 4b 20 [2] 65 02 [2] 71 19 [2] 7e 03 [2] 60 1e [2] 62 1f [2] 79 19 [2] 65 1e [2] 79 31 }

  condition:
    any of them
}