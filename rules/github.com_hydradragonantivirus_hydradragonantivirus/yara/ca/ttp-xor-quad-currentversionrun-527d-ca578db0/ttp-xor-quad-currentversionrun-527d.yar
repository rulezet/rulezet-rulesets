rule TTP_XOR_QUAD_CurrentVersionRun_527d {
  strings:
    $key_527d = { 01 12 [2] 25 1c [2] 0e 30 [2] 20 12 [2] 34 09 [2] 3b 13 [2] 25 0e [2] 27 0f [2] 3c 09 [2] 20 0e [2] 3c 21 }

  condition:
    any of them
}