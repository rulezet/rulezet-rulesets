rule TTP_XOR_QUAD_CurrentVersionRun_10ef {
  strings:
    $key_10ef = { 43 80 [2] 67 8e [2] 4c a2 [2] 62 80 [2] 76 9b [2] 79 81 [2] 67 9c [2] 65 9d [2] 7e 9b [2] 62 9c [2] 7e b3 }

  condition:
    any of them
}