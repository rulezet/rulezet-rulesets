rule TTP_XOR_QUAD_CurrentVersionRun_100c {
  strings:
    $key_100c = { 43 63 [2] 67 6d [2] 4c 41 [2] 62 63 [2] 76 78 [2] 79 62 [2] 67 7f [2] 65 7e [2] 7e 78 [2] 62 7f [2] 7e 50 }

  condition:
    any of them
}