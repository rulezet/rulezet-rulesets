rule TTP_XOR_QUAD_CurrentVersionRun_552a {
  strings:
    $key_552a = { 06 45 [2] 22 4b [2] 09 67 [2] 27 45 [2] 33 5e [2] 3c 44 [2] 22 59 [2] 20 58 [2] 3b 5e [2] 27 59 [2] 3b 76 }

  condition:
    any of them
}