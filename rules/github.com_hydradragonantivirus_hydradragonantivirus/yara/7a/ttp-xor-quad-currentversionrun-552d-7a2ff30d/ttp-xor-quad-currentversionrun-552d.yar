rule TTP_XOR_QUAD_CurrentVersionRun_552d {
  strings:
    $key_552d = { 06 42 [2] 22 4c [2] 09 60 [2] 27 42 [2] 33 59 [2] 3c 43 [2] 22 5e [2] 20 5f [2] 3b 59 [2] 27 5e [2] 3b 71 }

  condition:
    any of them
}