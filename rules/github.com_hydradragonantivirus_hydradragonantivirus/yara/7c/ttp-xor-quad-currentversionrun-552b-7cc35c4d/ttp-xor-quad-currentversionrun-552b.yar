rule TTP_XOR_QUAD_CurrentVersionRun_552b {
  strings:
    $key_552b = { 06 44 [2] 22 4a [2] 09 66 [2] 27 44 [2] 33 5f [2] 3c 45 [2] 22 58 [2] 20 59 [2] 3b 5f [2] 27 58 [2] 3b 77 }

  condition:
    any of them
}