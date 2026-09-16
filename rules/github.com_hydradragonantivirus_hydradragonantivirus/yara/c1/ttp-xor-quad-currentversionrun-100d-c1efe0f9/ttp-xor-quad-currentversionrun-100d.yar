rule TTP_XOR_QUAD_CurrentVersionRun_100d {
  strings:
    $key_100d = { 43 62 [2] 67 6c [2] 4c 40 [2] 62 62 [2] 76 79 [2] 79 63 [2] 67 7e [2] 65 7f [2] 7e 79 [2] 62 7e [2] 7e 51 }

  condition:
    any of them
}