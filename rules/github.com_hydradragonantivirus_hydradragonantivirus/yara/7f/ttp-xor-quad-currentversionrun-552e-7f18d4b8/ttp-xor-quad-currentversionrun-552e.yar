rule TTP_XOR_QUAD_CurrentVersionRun_552e {
  strings:
    $key_552e = { 06 41 [2] 22 4f [2] 09 63 [2] 27 41 [2] 33 5a [2] 3c 40 [2] 22 5d [2] 20 5c [2] 3b 5a [2] 27 5d [2] 3b 72 }

  condition:
    any of them
}